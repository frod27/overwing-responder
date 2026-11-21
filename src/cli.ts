#!/usr/bin/env node
/**
 * overwing-responder: carries out, on your side and with your own credentials, what an Overwing Radar
 * incident asks for, and reports back what it did.
 *
 *   overwing-responder check --config <file>                       validate the config and print each rule
 *   overwing-responder test  --config <file> --webhook <file>      what a saved webhook would lead to; runs nothing
 *   overwing-responder serve --config <file>                       receive webhooks and act
 *
 * `serve` reads the webhook secret from OVERWING_WEBHOOK_SECRET and refuses any request whose signature
 * does not match it. OVERWING_API_KEY (scope swarm is enough) is used only to report back; without it
 * the responder acts and reports nothing. Neither is ever given to a command. dry_run is on until the
 * config turns it off. What was acted on, what counts against the hourly cap and what waits for it are
 * kept in the state file, so a restart does not forget them.
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, fchmodSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { dirname, resolve as resolvePath } from "node:path";
import { ALWAYS_PASSED, commandEnv, drain, forget, newMemory, plan, readConfig, readState, reportUrl, verifySignature, writeState, type Asked, type Config, type Memory, type Step } from "./responder.ts";

/** Room for an incident that names 200 long identities under each of its actions. */
const MAX_BODY = 1024 * 1024;

const log = (o: Record<string, unknown>): void => void process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), ...o })}\n`);
const why = (e: unknown): string => (e instanceof Error ? e.message : "unknown");

function load(path: string | undefined): { config: Config; stateFile: string | null } {
  if (!path) throw new Error("--config <file> is required.");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e: unknown) {
    throw new Error(`Could not read ${path}: ${e instanceof Error ? e.message : "not JSON"}`);
  }
  const c = readConfig(raw);
  if (!c.ok) throw new Error(`Config: ${c.error}`);
  // A relative state_file is beside the config, wherever the responder is started from.
  return { config: c.value, stateFile: c.value.state_file === null ? null : resolvePath(dirname(path), c.value.state_file) };
}

/**
 * Reads the state file. A missing file is an empty memory. A file that is not the responder's state is an
 * error and never an empty memory: starting empty is what lets a replayed webhook run again.
 */
export function loadState(path: string): Memory {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return newMemory();
    throw new Error(`Could not read the state file ${path}: ${why(e)}`);
  }
  let state: ReturnType<typeof readState>;
  try {
    state = readState(JSON.parse(text));
  } catch {
    state = { ok: false, error: "it is not JSON" };
  }
  if (!state.ok) throw new Error(`The state file ${path} is corrupt: ${state.error}. Not starting: with its memory lost, a replayed webhook would run again and the hourly cap would start from zero. Repair the file, or move it away to start with an empty memory.`);
  return state.value;
}

/**
 * Writes the state file whole or not at all: a new file beside it, readable by this user only, then
 * renamed over it. `notStarted` are steps decided and not yet begun; see writeState.
 */
export function saveState(path: string, memory: Memory, nowMs: number, notStarted: readonly Asked[] = []): void {
  forget(memory, nowMs);
  const text = `${JSON.stringify(writeState(memory, notStarted), null, 2)}\n`;
  const temp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
  // "wx": the file must be new, so a link left at that name is not written through.
  const fd = openSync(temp, "wx", 0o600);
  try {
    try {
      fchmodSync(fd, 0o600);
      writeFileSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, path);
  } catch (e: unknown) {
    rmSync(temp, { force: true });
    throw e;
  }
}

function describe(c: Config, stateFile: string | null): string {
  const lines = [
    `Listens on ${c.listen.host}:${c.listen.port}. Reports to ${c.overwing_url}.`,
    c.dry_run ? "dry_run is ON: nothing is run. Each step is logged and reported as what would have been done." : "dry_run is OFF: matching commands are run.",
    `Acts on incidents of severity ${c.min_severity}${c.min_severity === "high" ? " and critical" : ""}, at most ${c.max_actions_per_hour} actions an hour, ${c.command_timeout_seconds} seconds a command. A step over the cap waits for room, 24 hours at most.`,
    stateFile ? `Keeps its memory in ${stateFile}.${c.dry_run ? " While dry_run is on it reads that file and adds nothing to it." : ""}` : "state_file is null: the memory is kept in the process only. After a restart, a webhook replayed within five minutes runs again, the hourly cap starts from zero and the steps that waited for it are lost.",
    `A command sees ${[...ALWAYS_PASSED, ...c.pass_env].join(", ")} of this environment, and nothing else of it.`,
    c.allow_private_sources ? "block_source acts on private, loopback and unspecified addresses too." : "block_source does not act on a private, loopback or unspecified address.",
    c.protect.length ? `Never acts on: ${c.protect.join("  ")}` : "No target is protected.",
    c.rules.length ? "Rules, first match wins:" : "No rules: nothing is ever run.",
    ...c.rules.map((r) => `  ${r.name}: ${r.action} of /${r.match}/${r.detectors ? ` found by ${r.detectors.join(", ")} only` : ""} runs ${JSON.stringify(r.run)}`),
  ];
  return lines.join("\n");
}

/** Runs one command with no shell, and with `env` as its whole environment. Its output is not kept beyond a short tail for the report. */
function run(argv: string[], timeoutSeconds: number, env: Record<string, string>): Promise<{ ok: boolean; detail: string }> {
  return new Promise((resolve) => {
    try {
      execFile(argv[0]!, argv.slice(1), { timeout: timeoutSeconds * 1000, maxBuffer: 1024 * 1024, windowsHide: true, env: env as NodeJS.ProcessEnv }, (err, _stdout, stderr) => {
        if (!err) return resolve({ ok: true, detail: "exit 0" });
        const code = (err as NodeJS.ErrnoException & { killed?: boolean }).killed ? "timed out" : `exit ${String((err as { code?: unknown }).code ?? "?")}`;
        resolve({ ok: false, detail: `${code}: ${String(stderr).trim().split("\n").pop()?.slice(0, 300) ?? ""}`.trim() });
      });
    } catch (e: unknown) {
      // A command that cannot even be started is one failed step, not the end of the steps after it.
      resolve({ ok: false, detail: `not started: ${why(e).slice(0, 300)}` });
    }
  });
}

async function report(url: string | null, key: string | undefined, body: Record<string, unknown>): Promise<void> {
  if (!url || !key) return;
  try {
    const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(15_000) });
    if (!r.ok) log({ event: "report_refused", status: r.status });
  } catch (e: unknown) {
    log({ event: "report_failed", error: e instanceof Error ? e.message : "unknown" });
  }
}

type Carrying = {
  config: Config;
  key?: string;
  name?: string;
  /** The whole environment of each command. */
  env: Record<string, string>;
  reportTo: (s: Step) => string | null;
  /** Called just before a step that was decided to run begins. */
  starting?: (s: Step) => void;
};

export async function carryOut(steps: readonly Step[], c: Carrying): Promise<void> {
  for (const s of steps) {
    let status: "done" | "failed" | "skipped" | "dry_run" = s.status === "skipped" ? "skipped" : "dry_run";
    let detail = s.reason ?? (s.rule ? `rule: ${s.rule}` : null);
    if (s.status !== "skipped") c.starting?.(s);
    if (s.status === "run" && s.argv) {
      const r = await run(s.argv, c.config.command_timeout_seconds, c.env);
      status = r.ok ? "done" : "failed";
      detail = `rule: ${s.rule}; ${r.detail}`;
    }
    log({ event: "step", incident: s.incident, action: s.action, target: s.target, rule: s.rule, status, detail });
    await report(c.reportTo(s), c.key, { action: s.action, target: s.target, status, detail: detail?.slice(0, 500) ?? null, by: (c.name ?? "overwing-responder").slice(0, 80) });
  }
}

function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        resolve(null);
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(null));
  });
}

/** `stateFile`: where the memory is kept; without it, in the process only. `tickMs` and `now` are for tests. */
export type Serving = { stateFile?: string | null; tickMs?: number; now?: () => number };

export function serve(config: Config, env: { secret: string; key?: string; name?: string }, memory: Memory = newMemory(), serving: Serving = {}): Server {
  const now = serving.now ?? Date.now;
  // Fixed at the start: PATH, HOME, LANG, TZ and what pass_env names. Never the webhook secret or the API key.
  const commandEnvironment = commandEnv(config, process.env);
  // One webhook's commands finish before the next one's start, so two incidents never race on one identity.
  let queue: Promise<void> = Promise.resolve();
  // Decided to run, and waiting for the commands before them. The state file keeps these as queued until they begin.
  const notStarted: Step[] = [];
  // A rehearsal leaves no mark: in dry_run the file is read at the start and not added to, so what
  // was only rehearsed neither counts as done nor uses the hourly cap once dry_run is turned off.
  const stateFile = config.dry_run ? null : serving.stateFile;
  const persist = (): void => {
    if (!stateFile) return forget(memory, now());
    try {
      saveState(stateFile, memory, now(), notStarted);
    } catch (e: unknown) {
      // The memory in the process is still whole, so the responder goes on. What a restart would know is out of date.
      log({ event: "state_save_failed", file: stateFile, error: why(e) });
    }
  };
  const starting = (s: Step): void => {
    const i = notStarted.indexOf(s);
    if (i >= 0) notStarted.splice(i, 1);
    persist();
  };
  const take = (steps: Step[], reportTo: string | null = null): void => {
    if (steps.length === 0) return;
    notStarted.push(...steps.filter((s) => s.status !== "skipped"));
    // Saved before the webhook is answered and before any command begins: what was decided is not decided again after a restart.
    persist();
    queue = queue
      .then(() => carryOut(steps, { config, key: env.key, name: env.name, env: commandEnvironment, reportTo: (s) => reportTo ?? reportUrl(config, s.incident), starting }))
      .catch((e: unknown) => log({ event: "error", error: why(e) }));
  };
  /** Runs what waited for the hourly cap and now has room, oldest first. */
  const tick = (at: number = now()): void => take(drain(config, memory, at));
  const server = createServer(async (req, res) => {
    const answer = (status: number, body: Record<string, unknown>): void => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method !== "POST") return answer(405, { error: "POST a signed Overwing webhook here." });
    const body = await readBody(req);
    if (body === null) return answer(413, { error: "Too large." });
    const at = now();
    const header = req.headers["x-overwing-signature"];
    const verified = verifySignature(env.secret, Array.isArray(header) ? header[0] : header, body, Math.floor(at / 1000));
    if (!verified.ok) {
      log({ event: "refused", reason: verified.error });
      return answer(401, { error: verified.error });
    }
    let webhook: unknown;
    try {
      webhook = JSON.parse(body);
    } catch {
      return answer(400, { error: "Not JSON." });
    }
    // What was queued earlier goes before what this webhook asks for.
    tick(at);
    const p = plan(webhook, config, memory, at);
    if (!p.ok) return answer(200, { received: true, steps: 0, note: p.error });
    take(p.steps, p.reportTo);
    // Answered at once: Overwing waits five seconds for a webhook, and a command may take longer.
    answer(202, { received: true, incident: p.incident, steps: p.steps.length });
  });
  // The cap is looked at once a minute for the steps that wait for it, for as long as the server is up.
  const timer = setInterval(() => tick(), serving.tickMs ?? 60_000);
  timer.unref();
  server.on("close", () => clearInterval(timer));
  server.listen(config.listen.port, config.listen.host);
  // What a restart found queued does not wait a minute more.
  tick();
  return server;
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (!command || command === "help" || command === "--help") {
    process.stdout.write("overwing-responder <check|test|serve> --config <file> [--webhook <file>]\n\n  check   validate the config and print each rule\n  test    what a saved webhook would lead to; runs nothing\n  serve   receive signed webhooks and act (OVERWING_WEBHOOK_SECRET; OVERWING_API_KEY to report back)\n");
    return 0;
  }
  const { config, stateFile } = load(flag(args, "--config"));
  if (command === "check") {
    process.stdout.write(`${describe(config, stateFile)}\n`);
    return 0;
  }
  if (command === "test") {
    const file = flag(args, "--webhook");
    if (!file) throw new Error("--webhook <file> is required: a saved webhook body.");
    // An empty memory, and nothing written: this shows what the config makes of a webhook, not what was done before.
    const p = plan(JSON.parse(readFileSync(file, "utf8")), { ...config, dry_run: true }, newMemory(), Date.now());
    if (!p.ok) throw new Error(p.error);
    if (p.steps.length === 0) process.stdout.write("Nothing to do: the webhook asks for no response, or the incident is below min_severity.\n");
    for (const s of p.steps) process.stdout.write(s.status === "skipped" ? `skip  ${s.action} ${s.target}: ${s.reason}\n` : `would run  [${s.rule}]  ${JSON.stringify(s.argv)}\n`);
    return 0;
  }
  if (command === "serve") {
    const secret = process.env.OVERWING_WEBHOOK_SECRET ?? "";
    if (!secret) throw new Error("OVERWING_WEBHOOK_SECRET is not set: the secret of your Overwing webhook. Without it no request can be trusted.");
    const memory = stateFile ? loadState(stateFile) : newMemory();
    if (stateFile) {
      try {
        // Written once before anything is accepted: a state file that cannot be kept is found out now, not during an incident.
        saveState(stateFile, memory, Date.now());
      } catch (e: unknown) {
        throw new Error(`Could not write the state file ${stateFile}: ${why(e)}. Set state_file to a path this user can write, or to null to keep the memory in the process only.`);
      }
    }
    process.stdout.write(`${describe(config, stateFile)}\n`);
    if (stateFile) process.stdout.write(`Remembers ${memory.done.size} targets acted on in the last seven days; ${memory.pending.length} steps wait for the hourly cap.\n`);
    if (!process.env.OVERWING_API_KEY) process.stdout.write("OVERWING_API_KEY is not set: steps are logged here and not reported to Overwing.\n");
    const server = serve(config, { secret, key: process.env.OVERWING_API_KEY, name: process.env.OVERWING_RESPONDER_NAME }, memory, { stateFile });
    const stop = (): void => void server.close(() => process.exit(0));
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    return await new Promise<number>(() => undefined);
  }
  throw new Error(`Unknown command: ${command}`);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(1);
    },
  );
}
