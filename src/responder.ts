/**
 * The rules of the responder: is this webhook really Overwing's, what does it ask for, and which of
 * this machine's own commands answer it. No network, no clock and no files in here; the server, the
 * command runner and the state file are in cli.ts. (`isIP` from node:net only reads a string.)
 *
 * The responder runs with the customer's own credentials, on the customer's side. Overwing never holds
 * them and never runs anything: it asks, in a signed webhook, and only when the account has switched
 * the response step on. Everything below is about doing less than was asked, never more:
 *   - nothing runs unless a rule in the customer's own config matches the target, in full;
 *   - a target named in `protect` is never acted on;
 *   - a command is an argument list, never a shell line; a target can only fill an argument, and what
 *     it fills cannot turn that argument into an option;
 *   - an address is blocked only if it is one address, and not a private one unless the config says so;
 *   - the same target is acted on once for an incident, however often the webhook repeats;
 *   - there is a cap on actions an hour (what is over it waits its turn, for a day at most), and
 *     `dry_run` is on until the customer turns it off.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

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
  /** When set, the rule answers only an action whose `detectors` are all in this list. */
  detectors?: string[];
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
  /** For block_source: act on private, loopback and unspecified addresses too. Off unless set: such an address is likely the customer's own. */
  allow_private_sources: boolean;
  /** Names of environment variables a command may see, besides PATH, HOME, LANG and TZ. */
  pass_env: string[];
  /** The file the memory is kept in between restarts; a relative path is beside the config. null keeps it in the process only. */
  state_file: string | null;
  rules: Rule[];
};

export const DEFAULTS = { listen: { host: "127.0.0.1", port: 8790 }, overwing_url: "https://overwing.ai", dry_run: true, min_severity: "critical" as const, max_actions_per_hour: 10, command_timeout_seconds: 30, protect: [] as string[], allow_private_sources: false, pass_env: [] as string[], state_file: "overwing-responder-state.json" as string | null };
/** No config can raise these. `queued` is how many steps may wait for the hourly cap at one time. */
export const CEILINGS = { max_actions_per_hour: 100, command_timeout_seconds: 300, rules: 100, queued: 1000 };

/** What a command sees of the responder's own environment, when set, before anything the config lists. */
export const ALWAYS_PASSED: readonly string[] = ["PATH", "HOME", "LANG", "TZ"];
/** What a command never sees, whatever the config lists. */
export const NEVER_PASSED: readonly string[] = ["OVERWING_WEBHOOK_SECRET", "OVERWING_API_KEY"];

const HOUR = 3_600_000;
/** A step that has waited this long for the hourly cap is not run. */
export const QUEUE_MS = 24 * HOUR;
/** How long an incident's target is remembered as acted on. */
export const REMEMBER_MS = 7 * 24 * HOUR;

type Read<T> = { ok: true; value: T } | { ok: false; error: string };
const bad = (error: string): { ok: false; error: string } => ({ ok: false, error });
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

// Anchored here, so a rule cannot match a part of a target by leaving the anchors out.
const anchored = (source: string): RegExp => new RegExp(`^(?:${source})$`);

function regex(source: unknown, what: string): Read<RegExp> {
  if (typeof source !== "string" || source.length === 0 || source.length > 500) return bad(`${what} must be a regular expression of 1 to 500 characters.`);
  try {
    return { ok: true, value: anchored(source) };
  } catch {
    return bad(`${what} is not a valid regular expression.`);
  }
}

/** The detectors an action says it comes from, or null when it names none that can be read. */
const readDetectors = (v: unknown): string[] | null => (Array.isArray(v) && v.length > 0 && v.length <= 20 && v.every((d) => typeof d === "string" && d.length > 0 && d.length <= 50) ? [...(v as string[])] : null);

export function readConfig(raw: unknown): Read<Config> {
  if (!isObject(raw)) return bad("The config must be an object.");
  const known = ["listen", "overwing_url", "dry_run", "min_severity", "max_actions_per_hour", "command_timeout_seconds", "protect", "allow_private_sources", "pass_env", "state_file", "rules"];
  const extra = Object.keys(raw).find((k) => !known.includes(k));
  if (extra) return bad(`Unknown field: ${extra}.`);
  const c: Config = { ...DEFAULTS, listen: { ...DEFAULTS.listen }, protect: [], pass_env: [], rules: [] };
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
  for (const k of ["dry_run", "allow_private_sources"] as const) {
    if (raw[k] === undefined) continue;
    if (typeof raw[k] !== "boolean") return bad(`${k} must be true or false.`);
    c[k] = raw[k] as boolean;
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
  if (raw.pass_env !== undefined) {
    if (!Array.isArray(raw.pass_env) || raw.pass_env.length > 50 || !raw.pass_env.every((n) => typeof n === "string" && /^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(n))) return bad("pass_env must be a list of at most 50 names of environment variables.");
    const names = raw.pass_env as string[];
    // Compared without regard to case: on Windows, overwing_api_key is the same variable.
    const secret = names.find((n) => NEVER_PASSED.includes(n.toUpperCase()));
    if (secret) return bad(`pass_env may not name ${secret}: a command never sees the webhook secret or the API key.`);
    c.pass_env = [...names];
  }
  if (raw.state_file !== undefined) {
    if (raw.state_file !== null && (typeof raw.state_file !== "string" || raw.state_file.length === 0 || raw.state_file.length > 1000 || raw.state_file.includes("\u0000"))) return bad("state_file must be a file path, or null to keep the memory in the process only.");
    c.state_file = raw.state_file;
  }
  if (!Array.isArray(raw.rules)) return bad("rules must be a list. With no rule, nothing is ever run.");
  if (raw.rules.length > CEILINGS.rules) return bad(`At most ${CEILINGS.rules} rules.`);
  for (const [i, r] of raw.rules.entries()) {
    if (!isObject(r)) return bad(`rules[${i}] must be an object.`);
    const extraRule = Object.keys(r).find((k) => !["name", "action", "match", "run", "detectors"].includes(k));
    if (extraRule) return bad(`rules[${i}]: unknown field ${extraRule}.`);
    if (typeof r.name !== "string" || r.name.length === 0 || r.name.length > 100) return bad(`rules[${i}].name must be 1 to 100 characters.`);
    if (!(ACTIONS as readonly unknown[]).includes(r.action)) return bad(`rules[${i}].action must be one of ${ACTIONS.join(", ")}.`);
    const m = regex(r.match, `rules[${i}].match`);
    if (!m.ok) return m;
    if (!Array.isArray(r.run) || r.run.length === 0 || r.run.length > 50 || !r.run.every((a) => typeof a === "string" && a.length <= 1000)) return bad(`rules[${i}].run must be a command as a list of 1 to 50 arguments. It is run as it is, with no shell.`);
    if (/[{}]/.test(r.run[0] as string)) return bad(`rules[${i}].run: the program itself is fixed. A target can only fill an argument.`);
    const rule: Rule = { name: r.name, action: r.action as ActionName, match: r.match as string, run: r.run as string[] };
    if (r.detectors !== undefined) {
      // An empty list would match nothing, or everything: neither is what anyone means.
      const detectors = readDetectors(r.detectors);
      if (!detectors) return bad(`rules[${i}].detectors must be a list of 1 to 20 detector names, such as decoy_touch.`);
      rule.detectors = detectors;
    }
    c.rules.push(rule);
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

/** Where an incident's steps are reported: Overwing's own address, from the config and never from a webhook. */
export function reportUrl(config: Pick<Config, "overwing_url">, incident: string): string | null {
  const base = reportOrigin(config.overwing_url);
  return base ? `${base}/api/v1/swarm/incidents/${incident}/responses` : null;
}

/**
 * The environment a command is run with: PATH, HOME, LANG and TZ when set, and what `pass_env` names.
 * Never the webhook secret or the API key, even if a config that was not read by readConfig lists them.
 */
export function commandEnv(config: Pick<Config, "pass_env">, env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of [...ALWAYS_PASSED, ...config.pass_env]) {
    const value = env[name];
    if (typeof value === "string" && !NEVER_PASSED.includes(name.toUpperCase())) out[name] = value;
  }
  return out;
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

/** One thing a webhook asked for, and when. This is what waits in the queue and what the state file keeps: never a command. */
export type Asked = { incident: string; action: ActionName; target: string; detectors: string[] | null; at: number };
export type Step = Asked & { rule: string | null; argv: string[] | null; status: "run" | "dry_run" | "skipped"; reason: string | null };

/**
 * What the responder remembers between webhooks: what it acted on and when (`done`), when the actions that
 * count against the hourly cap were decided (`times`), and what waits for the cap to have room (`pending`,
 * oldest first). cli.ts keeps it in the state file, so a restart does not forget it.
 */
export type Memory = { done: Map<string, number>; times: number[]; pending: Asked[] };
export const newMemory = (): Memory => ({ done: new Map(), times: [], pending: [] });

const INCIDENT = /^swi_[A-Za-z0-9_-]{20}$/;
/** None of the three parts can hold a line break, so the key reads back into them. */
export const keyOf = (a: Pick<Asked, "incident" | "action" | "target">): string => `${a.incident}\n${a.action}\n${a.target}`;
// A target is someone else's string. It may fill an argument; it may not be an option, or carry a line break.
const plainName = (target: string): boolean => target.length > 0 && target.length <= 300 && !/[\u0000-\u001f]/.test(target) && !target.startsWith("-");

const fill = (arg: string, target: string, groups: readonly (string | undefined)[]): string => arg.replace(/\{(target|[1-9])\}/g, (_, k: string) => (k === "target" ? target : (groups[Number(k)] ?? "")));

/** An IPv4 address that is somebody's own and not a place on the internet: "this network", private, shared, loopback, link-local. */
const localV4 = (a: number, b: number): boolean => a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);

/** The eight groups of an IPv6 address that isIP accepted, without a zone id. */
function groupsOf(address: string): number[] {
  let text = address;
  if (address.includes(".")) {
    // An IPv4 tail, as in ::ffff:10.0.0.1, is the last two groups.
    const cut = address.lastIndexOf(":") + 1;
    const [a = 0, b = 0, c = 0, d = 0] = address.slice(cut).split(".").map(Number);
    text = `${address.slice(0, cut)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = "", tail] = text.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const zeros = tail === undefined ? 0 : 8 - left.length - right.length;
  return [...left, ...Array<string>(zeros).fill("0"), ...right].map((g) => parseInt(g, 16));
}

/** Whether an address isIP accepted is unspecified, loopback, private, shared or link-local. */
function isLocal(address: string): boolean {
  if (isIP(address) === 4) {
    const [a = 0, b = 0] = address.split(".").map(Number);
    return localV4(a, b);
  }
  // A zone id (fe80::1%eth0) names a link of one machine.
  if (address.includes("%")) return true;
  const g = groupsOf(address);
  // ::, ::1 and an IPv4 address written as IPv6 (::ffff:10.0.0.1) are judged as the IPv4 address in the last two groups.
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0 || g[5] === 0xffff)) return localV4((g[6] ?? 0) >> 8, (g[6] ?? 0) & 0xff);
  // Unique local (fc00::/7), link-local (fe80::/10) and the old site-local (fec0::/10).
  return ((g[0] ?? 0) & 0xfe00) === 0xfc00 || ((g[0] ?? 0) & 0xff80) === 0xfe80;
}

/** For block_source: why this target is not acted on, or null. A range, a name or a list is not an address. */
function refuseSource(target: string, allowPrivate: boolean): string | null {
  const address = target.startsWith("ip:") ? target.slice(3) : "";
  if (isIP(address) === 0) return "not one address: block_source acts only on ip: followed by an IPv4 or IPv6 address";
  // The address a decoy key was tried from can be the customer's own gateway. Blocking it would be self-inflicted.
  if (!allowPrivate && isLocal(address)) return "a private, loopback or unspecified address, which is likely your own; allow_private_sources is off";
  return null;
}

type Compiled = { protect: RegExp[]; rules: { rule: Rule; match: RegExp }[] };
const compile = (config: Config): Compiled => ({ protect: config.protect.map(anchored), rules: config.rules.map((rule) => ({ rule, match: anchored(rule.match) })) });

/** Why a target is not acted on whatever the rules say, or null: not a plain name, protected, or not an address to block. */
function refuse(config: Config, compiled: Compiled, action: ActionName, target: string): string | null {
  if (!plainName(target)) return "the target is not a plain name";
  if (compiled.protect.some((p) => p.test(target))) return "protected by this responder's config";
  return action === "block_source" ? refuseSource(target, config.allow_private_sources) : null;
}

/**
 * The first rule that answers an action about a target, and its command with the target filled in; or why
 * there is none. Like `refuse`, asked again each time: a step that waited in the queue is held to the config
 * of the moment it runs.
 */
function command(compiled: Compiled, action: ActionName, target: string, detectors: readonly string[] | null): { rule: Rule; argv: string[] } | { reason: string } {
  for (const { rule, match } of compiled.rules) {
    if (rule.action !== action) continue;
    // A rule that names detectors answers only what those detectors found. An action that names none is not theirs.
    if (rule.detectors && !(detectors !== null && detectors.length > 0 && detectors.every((d) => rule.detectors?.includes(d)))) continue;
    const groups = match.exec(target);
    if (!groups) continue;
    const argv = [rule.run[0] as string];
    for (const template of rule.run.slice(1)) {
      const arg = fill(template, target, groups);
      // What a target fills stays a value. Only an argument the rule itself begins with "-" is an option.
      if (arg.startsWith("-") && !template.startsWith("-")) return { reason: `rule: ${rule.name}; a filled argument would begin with "-" and be read as an option` };
      argv.push(arg);
    }
    return { rule, argv };
  }
  return { reason: "no rule in this responder's config matches" };
}

/**
 * What to do about one webhook. Every target the webhook names gets a step: to run, or skipped with the
 * reason. `memory` is updated for the steps that will run, so calling this is deciding to run them. A step
 * over the hourly cap is skipped for now and put in `memory.pending`: `drain` decides it later. Call `drain`
 * first, so that what was queued earlier goes first.
 */
export function plan(webhook: unknown, config: Config, memory: Memory, nowMs: number): { ok: true; incident: string; reportTo: string | null; steps: Step[] } | { ok: false; error: string } {
  if (!isObject(webhook) || !isObject(webhook.data)) return bad("Not a webhook.");
  if (webhook.type !== "swarm.incident.opened" && webhook.type !== "swarm.incident.updated") return bad("Not a Radar incident webhook.");
  const d = webhook.data;
  const incident = typeof d.id === "string" && INCIDENT.test(d.id) ? d.id : null;
  if (!incident) return bad("The webhook names no incident.");
  const response = isObject(d.response) ? d.response : null;
  // Overwing asks only when the account switched the response step on. No request, nothing to do.
  if (!response || response.requested !== true || !Array.isArray(response.actions)) return { ok: true, incident, reportTo: null, steps: [] };
  // An own property only: "toString" is in every object, and is not a severity.
  const severity = typeof d.severity === "string" && Object.hasOwn(SEVERITY, d.severity) ? (d.severity as Severity) : "low";
  if (SEVERITY[severity] < SEVERITY[config.min_severity]) return { ok: true, incident, reportTo: null, steps: [] };

  // A report goes to Overwing's own address and nowhere else, whatever the webhook says.
  const own = reportUrl(config, incident);
  const wanted = typeof response.report_to === "string" ? response.report_to : "";
  const reportTo = own && wanted.startsWith(own) ? wanted : own;

  const compiled = compile(config);
  memory.times = memory.times.filter((t) => t > nowMs - HOUR);
  const queued = new Set(memory.pending.map(keyOf));
  const steps: Step[] = [];
  for (const a of response.actions) {
    if (!isObject(a) || !(ACTIONS as readonly unknown[]).includes(a.action)) continue;
    const action = a.action as ActionName;
    const detectors = readDetectors(a.detectors);
    const targets = Array.isArray(a.actors) && a.actors.length ? a.actors : typeof a.surface === "string" ? [a.surface] : [];
    for (const target of targets.slice(0, 200)) {
      if (typeof target !== "string") continue;
      const asked: Asked = { incident, action, target: target.slice(0, 300), detectors, at: nowMs };
      const skip = (reason: string): void => void steps.push({ ...asked, rule: null, argv: null, status: "skipped", reason });
      const refused = refuse(config, compiled, action, target);
      if (refused) { skip(refused); continue; }
      // Once for an incident: a target that was acted on, or waits to be, is not looked at again, whichever rule would answer now.
      const key = keyOf(asked);
      if (memory.done.has(key) || queued.has(key)) continue;
      const decided = command(compiled, action, target, detectors);
      if ("reason" in decided) { skip(decided.reason); continue; }
      if (memory.times.length >= config.max_actions_per_hour) {
        const over = `over this responder's cap of ${config.max_actions_per_hour} actions an hour`;
        if (memory.pending.length >= CEILINGS.queued) { skip(`${over}, and ${CEILINGS.queued} steps already wait: not queued`); continue; }
        memory.pending.push(asked);
        queued.add(key);
        skip(`${over}; queued to run when the cap has room`);
        continue;
      }
      memory.done.set(key, nowMs);
      memory.times.push(nowMs);
      steps.push({ ...asked, rule: decided.rule.name, argv: decided.argv, status: config.dry_run ? "dry_run" : "run", reason: null });
    }
  }
  return { ok: true, incident, reportTo, steps };
}

/**
 * The queued steps that are decided now, oldest first: to run because the hourly cap has room, or skipped
 * because they waited more than 24 hours or the config no longer allows them. The others stay queued. As
 * with `plan`, `memory` is updated for the steps that will run.
 */
export function drain(config: Config, memory: Memory, nowMs: number): Step[] {
  memory.times = memory.times.filter((t) => t > nowMs - HOUR);
  const compiled = compile(config);
  const steps: Step[] = [];
  const waiting: Asked[] = [];
  const seen = new Set<string>();
  for (const asked of [...memory.pending].sort((a, b) => a.at - b.at)) {
    const key = keyOf(asked);
    if (memory.done.has(key) || seen.has(key)) continue;
    seen.add(key);
    const skip = (reason: string): void => void steps.push({ ...asked, rule: null, argv: null, status: "skipped", reason });
    if (nowMs - asked.at > QUEUE_MS) { skip("queued for more than 24 hours behind this responder's hourly cap: not run"); continue; }
    const refused = refuse(config, compiled, asked.action, asked.target);
    if (refused) { skip(refused); continue; }
    const decided = command(compiled, asked.action, asked.target, asked.detectors);
    if ("reason" in decided) { skip(decided.reason); continue; }
    if (memory.times.length >= config.max_actions_per_hour) { waiting.push(asked); continue; }
    memory.done.set(key, nowMs);
    memory.times.push(nowMs);
    steps.push({ ...asked, rule: decided.rule.name, argv: decided.argv, status: config.dry_run ? "dry_run" : "run", reason: null });
  }
  memory.pending = waiting;
  return steps;
}

/** Drops what no longer matters: an action decided an hour ago no longer counts against the cap, and a target acted on more than seven days ago is no longer remembered. */
export function forget(memory: Memory, nowMs: number): void {
  for (const [key, at] of memory.done) if (at < nowMs - REMEMBER_MS) memory.done.delete(key);
  memory.times = memory.times.filter((t) => t > nowMs - HOUR);
}

const isTime = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

function readAsked(v: unknown): Asked | null {
  if (!isObject(v)) return null;
  if (typeof v.incident !== "string" || !INCIDENT.test(v.incident)) return null;
  if (!(ACTIONS as readonly unknown[]).includes(v.action)) return null;
  if (typeof v.target !== "string" || !plainName(v.target) || !isTime(v.at)) return null;
  const detectors = v.detectors === undefined || v.detectors === null ? null : readDetectors(v.detectors);
  if (v.detectors !== undefined && v.detectors !== null && detectors === null) return null;
  return { incident: v.incident, action: v.action as ActionName, target: v.target, detectors, at: v.at };
}

/**
 * The memory as the state file holds it. `notStarted` are steps that were decided and whose commands have
 * not started: they are written as still queued and not as done, so a restart runs them and does not lose
 * them. Their place under the hourly cap stays counted, which errs towards running later.
 */
export function writeState(memory: Memory, notStarted: readonly Asked[] = []): Record<string, unknown> {
  const held = new Set(notStarted.map(keyOf));
  const asked = ({ incident, action, target, detectors, at }: Asked): Asked => ({ incident, action, target, detectors, at });
  const done = [...memory.done].filter(([key]) => !held.has(key)).map(([key, at]) => {
    const [incident, action, target] = key.split("\n");
    return { incident, action, target, at };
  });
  return { version: 1, done, times: [...memory.times], pending: [...notStarted, ...memory.pending].map(asked) };
}

/** Reads what `writeState` wrote. Anything else is an error, never an empty memory: forgetting is what a replay needs. */
export function readState(raw: unknown): Read<Memory> {
  if (!isObject(raw) || raw.version !== 1) return bad("it is not version 1 of a responder's state");
  if (!Array.isArray(raw.done) || !Array.isArray(raw.times) || !Array.isArray(raw.pending)) return bad("done, times and pending must each be a list");
  const memory = newMemory();
  for (const [i, v] of raw.done.entries()) {
    const a = readAsked(v);
    if (!a) return bad(`done[${i}] is not an incident, an action, a target and a time`);
    memory.done.set(keyOf(a), a.at);
  }
  for (const [i, t] of raw.times.entries()) {
    if (!isTime(t)) return bad(`times[${i}] is not a time`);
    memory.times.push(t);
  }
  for (const [i, v] of raw.pending.entries()) {
    const a = readAsked(v);
    if (!a) return bad(`pending[${i}] is not an incident, an action, a target and a time`);
    memory.pending.push(a);
  }
  return { ok: true, value: memory };
}
