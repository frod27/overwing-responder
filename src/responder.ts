/**
 * The rules of the responder: is this webhook really Overwing's, what does it ask for, and which of
 * this machine's own commands answer it. No network and no clock in here; the server and the command
 * runner are in cli.ts.
 *
 * The responder runs with the customer's own credentials, on the customer's side. Overwing never holds
 * them and never runs anything: it asks, in a signed webhook, and only when the account has switched
 * the response step on. Everything below is about doing less than was asked, never more:
 *   - nothing runs unless a rule in the customer's own config matches the target, in full;
 *   - a target named in `protect` is never acted on;
 *   - a command is an argument list, never a shell line, and a target can only fill an argument;
 *   - the same target is acted on once for an incident, however often the webhook repeats;
 *   - there is a cap on actions an hour, and `dry_run` is on until the customer turns it off.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const ACTIONS = ["revoke_identity", "block_source", "rotate_secrets", "quarantine_surface"] as const;
export type ActionName = (typeof ACTIONS)[number];
const SEVERITY = { low: 0, medium: 1, high: 2, critical: 3 } as const;
export type Severity = keyof typeof SEVERITY;

export type Rule = {
  name: string;
  action: ActionName;
  /** A regular expression the whole target must match. Its numbered groups can fill the command: {1} to {9}. */
  match: string;
  /** The command as an argument list. {target} and {1}..{9} are replaced inside an argument. */
  run: string[];
};

export type Config = {
  listen: { host: string; port: number };
  /** Where reports go, and the only host a report is ever sent to. */
  overwing_url: string;
  /** On until turned off: the responder logs and reports what it would run, and runs nothing. */
  dry_run: boolean;
  min_severity: "high" | "critical";
  max_actions_per_hour: number;
  command_timeout_seconds: number;
  /** Regular expressions. A target that matches one, in full, is never acted on. */
  protect: string[];
  rules: Rule[];
};

export const DEFAULTS = { listen: { host: "127.0.0.1", port: 8790 }, overwing_url: "https://overwing.ai", dry_run: true, min_severity: "critical" as const, max_actions_per_hour: 10, command_timeout_seconds: 30, protect: [] as string[] };
/** No config can raise these. */
export const CEILINGS = { max_actions_per_hour: 100, command_timeout_seconds: 300, rules: 100 };

type Read<T> = { ok: true; value: T } | { ok: false; error: string };
const bad = (error: string): { ok: false; error: string } => ({ ok: false, error });
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function regex(source: unknown, what: string): Read<RegExp> {
  if (typeof source !== "string" || source.length === 0 || source.length > 500) return bad(`${what} must be a regular expression of 1 to 500 characters.`);
  try {
    // Anchored here, so a rule cannot match a part of a target by leaving the anchors out.
    return { ok: true, value: new RegExp(`^(?:${source})$`) };
  } catch {
    return bad(`${what} is not a valid regular expression.`);
  }
}

export function readConfig(raw: unknown): Read<Config> {
  if (!isObject(raw)) return bad("The config must be an object.");
  const known = ["listen", "overwing_url", "dry_run", "min_severity", "max_actions_per_hour", "command_timeout_seconds", "protect", "rules"];
  const extra = Object.keys(raw).find((k) => !known.includes(k));
  if (extra) return bad(`Unknown field: ${extra}.`);
  const c: Config = { ...DEFAULTS, listen: { ...DEFAULTS.listen }, protect: [], rules: [] };
  if (raw.listen !== undefined) {
    if (!isObject(raw.listen)) return bad("listen must be { host, port }.");
    if (raw.listen.host !== undefined) {
      if (typeof raw.listen.host !== "string" || !/^[A-Za-z0-9.:-]{1,100}$/.test(raw.listen.host)) return bad("listen.host must be a host name or address.");
      c.listen.host = raw.listen.host;
    }
    if (raw.listen.port !== undefined) {
      if (!Number.isInteger(raw.listen.port) || (raw.listen.port as number) < 0 || (raw.listen.port as number) > 65535) return bad("listen.port must be a port number.");
      c.listen.port = raw.listen.port as number;
    }
  }
  if (raw.overwing_url !== undefined) {
    if (typeof raw.overwing_url !== "string" || !reportOrigin(raw.overwing_url)) return bad("overwing_url must be an https address (http is accepted for localhost only).");
    c.overwing_url = raw.overwing_url;
  }
  if (raw.dry_run !== undefined) {
    if (typeof raw.dry_run !== "boolean") return bad("dry_run must be true or false.");
    c.dry_run = raw.dry_run;
  }
  if (raw.min_severity !== undefined) {
    if (raw.min_severity !== "high" && raw.min_severity !== "critical") return bad('min_severity must be "high" or "critical".');
    c.min_severity = raw.min_severity;
  }
  for (const k of ["max_actions_per_hour", "command_timeout_seconds"] as const) {
    if (raw[k] === undefined) continue;
    if (!Number.isInteger(raw[k]) || (raw[k] as number) < 1 || (raw[k] as number) > CEILINGS[k]) return bad(`${k} must be a whole number from 1 to ${CEILINGS[k]}.`);
    c[k] = raw[k] as number;
  }
  if (raw.protect !== undefined) {
    if (!Array.isArray(raw.protect) || raw.protect.length > 200) return bad("protect must be a list of at most 200 regular expressions.");
    for (const [i, p] of raw.protect.entries()) {
      const r = regex(p, `protect[${i}]`);
      if (!r.ok) return r;
      c.protect.push(p as string);
    }
  }
  if (!Array.isArray(raw.rules)) return bad("rules must be a list. With no rule, nothing is ever run.");
  if (raw.rules.length > CEILINGS.rules) return bad(`At most ${CEILINGS.rules} rules.`);
  for (const [i, r] of raw.rules.entries()) {
    if (!isObject(r)) return bad(`rules[${i}] must be an object.`);
    const extraRule = Object.keys(r).find((k) => !["name", "action", "match", "run"].includes(k));
    if (extraRule) return bad(`rules[${i}]: unknown field ${extraRule}.`);
    if (typeof r.name !== "string" || r.name.length === 0 || r.name.length > 100) return bad(`rules[${i}].name must be 1 to 100 characters.`);
    if (!(ACTIONS as readonly unknown[]).includes(r.action)) return bad(`rules[${i}].action must be one of ${ACTIONS.join(", ")}.`);
    const m = regex(r.match, `rules[${i}].match`);
    if (!m.ok) return m;
    if (!Array.isArray(r.run) || r.run.length === 0 || r.run.length > 50 || !r.run.every((a) => typeof a === "string" && a.length <= 1000)) return bad(`rules[${i}].run must be a command as a list of 1 to 50 arguments. It is run as it is, with no shell.`);
    if (/[{}]/.test(r.run[0] as string)) return bad(`rules[${i}].run: the program itself is fixed. A target can only fill an argument.`);
    c.rules.push({ name: r.name, action: r.action as ActionName, match: r.match as string, run: r.run as string[] });
  }
  return { ok: true, value: c };
}

/** The origin a report may be sent to, or null: https anywhere, http on this machine only. */
export function reportOrigin(url: string): string | null {
  try {
    const u = new URL(url);
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.protocol === "https:" || (u.protocol === "http:" && local)) return u.origin;
  } catch {
    // Not an address.
  }
  return null;
}

/** How old a webhook may be. An older one is a replay, or a clock that is wrong. */
export const TOLERANCE_SECONDS = 300;

/** Checks "X-Overwing-Signature: t=<unix seconds>,v1=<hex hmac of `${t}.${body}`>". */
export function verifySignature(secret: string, header: string | null | undefined, body: string, nowSeconds: number): { ok: true } | { ok: false; error: string } {
  if (!secret) return bad("No webhook secret is set.");
  if (!header) return bad("No signature.");
  let t: number | null = null;
  let v1: string | null = null;
  for (const part of header.split(",")) {
    const [k, v] = part.trim().split("=");
    if (k === "t" && v && /^\d{1,12}$/.test(v)) t = Number(v);
    else if (k === "v1" && v && /^[0-9a-f]{64}$/.test(v)) v1 = v;
  }
  if (t === null || v1 === null) return bad("The signature is not in the form t=...,v1=....");
  if (Math.abs(nowSeconds - t) > TOLERANCE_SECONDS) return bad("The signature is too old, or this machine's clock is wrong.");
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest();
  const given = Buffer.from(v1, "hex");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return bad("The signature does not match.");
  return { ok: true };
}

export type Step = { incident: string; action: ActionName; target: string; rule: string | null; argv: string[] | null; status: "run" | "dry_run" | "skipped"; reason: string | null };

/** What the responder remembers between webhooks. Lost on a restart, which errs towards acting again, once. */
export type Memory = { done: Set<string>; times: number[] };
export const newMemory = (): Memory => ({ done: new Set(), times: [] });

const fill = (arg: string, target: string, groups: readonly (string | undefined)[]): string => arg.replace(/\{(target|[1-9])\}/g, (_, k: string) => (k === "target" ? target : (groups[Number(k)] ?? "")));

/**
 * What to do about one webhook. Every target the webhook names gets a step: to run, or skipped with the
 * reason. `memory` is updated for the steps that will run, so calling this is deciding to run them.
 */
export function plan(webhook: unknown, config: Config, memory: Memory, nowMs: number): { ok: true; incident: string; reportTo: string | null; steps: Step[] } | { ok: false; error: string } {
  if (!isObject(webhook) || !isObject(webhook.data)) return bad("Not a webhook.");
  if (webhook.type !== "swarm.incident.opened" && webhook.type !== "swarm.incident.updated") return bad("Not a Radar incident webhook.");
  const d = webhook.data;
  const incident = typeof d.id === "string" && /^swi_[A-Za-z0-9_-]{20}$/.test(d.id) ? d.id : null;
  if (!incident) return bad("The webhook names no incident.");
  const response = isObject(d.response) ? d.response : null;
  // Overwing asks only when the account switched the response step on. No request, nothing to do.
  if (!response || response.requested !== true || !Array.isArray(response.actions)) return { ok: true, incident, reportTo: null, steps: [] };
  const severity = typeof d.severity === "string" && d.severity in SEVERITY ? (d.severity as Severity) : "low";
  if (SEVERITY[severity] < SEVERITY[config.min_severity]) return { ok: true, incident, reportTo: null, steps: [] };

  // A report goes to Overwing's own address and nowhere else, whatever the webhook says.
  const base = reportOrigin(config.overwing_url);
  const wanted = typeof response.report_to === "string" ? response.report_to : "";
  const reportTo = base && wanted.startsWith(`${base}/api/v1/swarm/incidents/${incident}/responses`) ? wanted : base ? `${base}/api/v1/swarm/incidents/${incident}/responses` : null;

  const protect = config.protect.map((p) => new RegExp(`^(?:${p})$`));
  const hourAgo = nowMs - 3_600_000;
  memory.times = memory.times.filter((t) => t > hourAgo);
  const steps: Step[] = [];
  for (const a of response.actions) {
    if (!isObject(a) || !(ACTIONS as readonly unknown[]).includes(a.action)) continue;
    const action = a.action as ActionName;
    const targets = Array.isArray(a.actors) && a.actors.length ? a.actors : typeof a.surface === "string" ? [a.surface] : [];
    for (const raw of targets.slice(0, 200)) {
      if (typeof raw !== "string") continue;
      const target = raw;
      const skip = (reason: string): void => void steps.push({ incident, action, target: target.slice(0, 300), rule: null, argv: null, status: "skipped", reason });
      // A target is someone else's string. It may fill an argument; it may not be an option, or carry a line break.
      if (target.length === 0 || target.length > 300 || /[\u0000-\u001f]/.test(target) || target.startsWith("-")) { skip("the target is not a plain name"); continue; }
      if (protect.some((p) => p.test(target))) { skip("protected by this responder's config"); continue; }
      const key = `${incident}\n${action}\n${target}`;
      if (memory.done.has(key)) continue;
      let matched: { rule: Rule; groups: RegExpExecArray } | null = null;
      for (const rule of config.rules) {
        if (rule.action !== action) continue;
        const m = new RegExp(`^(?:${rule.match})$`).exec(target);
        if (m) { matched = { rule, groups: m }; break; }
      }
      if (!matched) { skip("no rule in this responder's config matches"); continue; }
      if (memory.times.length >= config.max_actions_per_hour) { skip(`over this responder's cap of ${config.max_actions_per_hour} actions an hour`); continue; }
      const argv = matched.rule.run.map((arg, i) => (i === 0 ? arg : fill(arg, target, matched!.groups)));
      memory.done.add(key);
      memory.times.push(nowMs);
      steps.push({ incident, action, target, rule: matched.rule.name, argv, status: config.dry_run ? "dry_run" : "run", reason: null });
    }
  }
  return { ok: true, incident, reportTo, steps };
}
