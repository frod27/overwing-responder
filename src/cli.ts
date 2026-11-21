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
 * the responder acts and reports nothing. dry_run is on until the config turns it off.
 */
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { newMemory, plan, readConfig, verifySignature, type Config, type Memory, type Step } from "./responder.ts";

const MAX_BODY = 256 * 1024;

const log = (o: Record<string, unknown>): void => void process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), ...o })}\n`);

function load(path: string | undefined): Config {
  if (!path) throw new Error("--config <file> is required.");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e: unknown) {
    throw new Error(`Could not read ${path}: ${e instanceof Error ? e.message : "not JSON"}`);
  }
  const c = readConfig(raw);
  if (!c.ok) throw new Error(`Config: ${c.error}`);
  return c.value;
}

function describe(c: Config): string {
  const lines = [
    `Listens on ${c.listen.host}:${c.listen.port}. Reports to ${c.overwing_url}.`,
    c.dry_run ? "dry_run is ON: nothing is run. Each step is logged and reported as what would have been done." : "dry_run is OFF: matching commands are run.",
    `Acts on incidents of severity ${c.min_severity}${c.min_severity === "high" ? " and critical" : ""}, at most ${c.max_actions_per_hour} actions an hour, ${c.command_timeout_seconds} seconds a command.`,
    c.protect.length ? `Never acts on: ${c.protect.join("  ")}` : "No target is protected.",
    c.rules.length ? "Rules, first match wins:" : "No rules: nothing is ever run.",
    ...c.rules.map((r) => `  ${r.name}: ${r.action} of /${r.match}/ runs ${JSON.stringify(r.run)}`),
  ];
  return lines.join("\n");
}

/** Runs one command with no shell. Its output is not kept beyond a short tail for the report. */
function run(argv: string[], timeoutSeconds: number): Promise<{ ok: boolean; detail: string }> {
  return new Promise((resolve) => {
    execFile(argv[0]!, argv.slice(1), { timeout: timeoutSeconds * 1000, maxBuffer: 1024 * 1024, windowsHide: true }, (err, _stdout, stderr) => {
      if (!err) return resolve({ ok: true, detail: "exit 0" });
      const code = (err as NodeJS.ErrnoException & { killed?: boolean }).killed ? "timed out" : `exit ${String((err as { code?: unknown }).code ?? "?")}`;
      resolve({ ok: false, detail: `${code}: ${String(stderr).trim().split("\n").pop()?.slice(0, 300) ?? ""}`.trim() });
    });
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

export async function carryOut(steps: readonly Step[], reportTo: string | null, config: Config, env: { key?: string; name?: string }): Promise<void> {
  for (const s of steps) {
    let status: "done" | "failed" | "skipped" | "dry_run" = s.status === "skipped" ? "skipped" : "dry_run";
    let detail = s.reason ?? (s.rule ? `rule: ${s.rule}` : null);
    if (s.status === "run" && s.argv) {
      const r = await run(s.argv, config.command_timeout_seconds);
      status = r.ok ? "done" : "failed";
      detail = `rule: ${s.rule}; ${r.detail}`;
    }
    log({ event: "step", incident: s.incident, action: s.action, target: s.target, rule: s.rule, status, detail });
    await report(reportTo, env.key, { action: s.action, target: s.target, status, detail: detail?.slice(0, 500) ?? null, by: (env.name ?? "overwing-responder").slice(0, 80) });
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

export function serve(config: Config, env: { secret: string; key?: string; name?: string }, memory: Memory = newMemory()): Server {
  // One webhook's commands finish before the next one's start, so two incidents never race on one identity.
  let queue: Promise<void> = Promise.resolve();
  const server = createServer(async (req, res) => {
    const answer = (status: number, body: Record<string, unknown>): void => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method !== "POST") return answer(405, { error: "POST a signed Overwing webhook here." });
    const body = await readBody(req);
    if (body === null) return answer(413, { error: "Too large." });
    const header = req.headers["x-overwing-signature"];
    const verified = verifySignature(env.secret, Array.isArray(header) ? header[0] : header, body, Math.floor(Date.now() / 1000));
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
    const p = plan(webhook, config, memory, Date.now());
    if (!p.ok) return answer(200, { received: true, steps: 0, note: p.error });
    // Answered at once: Overwing waits five seconds for a webhook, and a command may take longer.
    answer(202, { received: true, incident: p.incident, steps: p.steps.length });
    queue = queue.then(() => carryOut(p.steps, p.reportTo, config, env)).catch((e: unknown) => log({ event: "error", error: e instanceof Error ? e.message : "unknown" }));
  });
  server.listen(config.listen.port, config.listen.host);
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
  const config = load(flag(args, "--config"));
  if (command === "check") {
    process.stdout.write(`${describe(config)}\n`);
    return 0;
  }
  if (command === "test") {
    const file = flag(args, "--webhook");
    if (!file) throw new Error("--webhook <file> is required: a saved webhook body.");
    const p = plan(JSON.parse(readFileSync(file, "utf8")), { ...config, dry_run: true }, newMemory(), Date.now());
    if (!p.ok) throw new Error(p.error);
    if (p.steps.length === 0) process.stdout.write("Nothing to do: the webhook asks for no response, or the incident is below min_severity.\n");
    for (const s of p.steps) process.stdout.write(s.status === "skipped" ? `skip  ${s.action} ${s.target}: ${s.reason}\n` : `would run  [${s.rule}]  ${JSON.stringify(s.argv)}\n`);
    return 0;
  }
  if (command === "serve") {
    const secret = process.env.OVERWING_WEBHOOK_SECRET ?? "";
    if (!secret) throw new Error("OVERWING_WEBHOOK_SECRET is not set: the secret of your Overwing webhook. Without it no request can be trusted.");
    process.stdout.write(`${describe(config)}\n`);
    if (!process.env.OVERWING_API_KEY) process.stdout.write("OVERWING_API_KEY is not set: steps are logged here and not reported to Overwing.\n");
    const server = serve(config, { secret, key: process.env.OVERWING_API_KEY, name: process.env.OVERWING_RESPONDER_NAME });
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
