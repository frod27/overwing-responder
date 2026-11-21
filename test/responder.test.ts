import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "../src/cli.ts";
import { newMemory, plan, readConfig, reportOrigin, verifySignature, type Config } from "../src/responder.ts";

const SECRET = "whsec_test_secret";
const INCIDENT = "swi_AbCdEfGhIj0123456789";
const sign = (body: string, t = Math.floor(Date.now() / 1000), secret = SECRET): string => `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;

const config = (over: Record<string, unknown> = {}): Config => {
  const c = readConfig({
    dry_run: false,
    rules: [
      { name: "quarantine an IAM user", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/([A-Za-z0-9+=,.@_-]{1,64})", run: ["aws", "iam", "put-user-policy", "--user-name", "{1}", "--policy-name", "overwing-quarantine", "--policy-document", "file://deny-all.json"] },
      { name: "block an address", action: "block_source", match: "ip:(\\d{1,3}(?:\\.\\d{1,3}){3})", run: ["/usr/local/bin/block-ip", "{1}/32", "--reason={target}"] },
    ],
    ...over,
  });
  if (!c.ok) throw new Error(c.error);
  return c.value;
};

const webhook = (over: Record<string, unknown> = {}, response: unknown = undefined): Record<string, unknown> => ({
  type: "swarm.incident.opened",
  created_at: new Date().toISOString(),
  data: {
    id: INCIDENT,
    status: "open",
    severity: "critical",
    title: "Sweep + Decoy touched on s3://acme",
    detectors: ["sweep", "decoy_touch"],
    surfaces: ["s3://acme"],
    actors: ["arn:aws:iam::111122223333:user/svc-reports"],
    recommended_actions: [],
    response: response ?? {
      requested: true,
      actions: [
        { action: "revoke_identity", surface: null, actors: ["arn:aws:iam::111122223333:user/svc-reports"], reason: "stolen" },
        { action: "block_source", surface: null, actors: ["ip:203.0.113.7"], reason: "tried a decoy key" },
        { action: "rotate_secrets", surface: "ci-secrets", reason: "decoy key tried" },
      ],
      report_to: `https://overwing.ai/api/v1/swarm/incidents/${INCIDENT}/responses`,
    },
    url: `https://overwing.ai/dashboard/swarm/incidents/${INCIDENT}`,
    ...over,
  },
});

describe("responder: the signature", () => {
  const body = JSON.stringify(webhook());
  const now = Math.floor(Date.now() / 1000);
  it("accepts Overwing's signature over the exact body", () => {
    assert.deepEqual(verifySignature(SECRET, sign(body, now), body, now), { ok: true });
  });
  it("refuses another secret, a changed body, a stale time and anything malformed", () => {
    assert.equal(verifySignature(SECRET, sign(body, now, "other"), body, now).ok, false);
    assert.equal(verifySignature(SECRET, sign(body, now), `${body} `, now).ok, false);
    assert.equal(verifySignature(SECRET, sign(body, now - 301), body, now).ok, false);
    assert.equal(verifySignature(SECRET, sign(body, now + 301), body, now).ok, false);
    for (const h of [null, undefined, "", "v1=abc", `t=${now}`, `t=${now},v1=zz`, "garbage"]) assert.equal(verifySignature(SECRET, h, body, now).ok, false, String(h));
    assert.equal(verifySignature("", sign(body, now, ""), body, now).ok, false, "no secret set means nothing is trusted");
  });
});

describe("responder: the config", () => {
  it("starts with dry_run on, critical only, and nothing run without a rule", () => {
    const c = readConfig({ rules: [] });
    assert.ok(c.ok);
    assert.deepEqual([c.value.dry_run, c.value.min_severity, c.value.max_actions_per_hour, c.value.listen.host], [true, "critical", 10, "127.0.0.1"]);
    assert.equal(readConfig({}).ok, false, "rules must be stated, even when empty");
  });
  it("refuses what would let a target choose the program, a shell line, an unknown field or a limit above the ceiling", () => {
    const rule = { name: "r", action: "revoke_identity", match: ".+", run: ["true"] };
    assert.equal(readConfig({ rules: [{ ...rule, run: ["{target}"] }] }).ok, false);
    assert.equal(readConfig({ rules: [{ ...rule, run: "aws iam delete-user {target}" }] }).ok, false);
    assert.equal(readConfig({ rules: [{ ...rule, shell: true }] }).ok, false);
    assert.equal(readConfig({ rules: [{ ...rule, action: "delete_everything" }] }).ok, false);
    assert.equal(readConfig({ rules: [{ ...rule, match: "(" }] }).ok, false);
    assert.equal(readConfig({ rules: [rule], max_actions_per_hour: 101 }).ok, false);
    assert.equal(readConfig({ rules: [rule], command_timeout_seconds: 301 }).ok, false);
    assert.equal(readConfig({ rules: [rule], extra: 1 }).ok, false);
    assert.equal(readConfig({ rules: [rule], overwing_url: "http://example.com" }).ok, false);
    assert.equal(readConfig({ rules: [rule], protect: ["("] }).ok, false);
  });
  it("reports to https, or to this machine, and nowhere else", () => {
    assert.equal(reportOrigin("https://overwing.ai/x"), "https://overwing.ai");
    assert.equal(reportOrigin("http://127.0.0.1:9000"), "http://127.0.0.1:9000");
    assert.equal(reportOrigin("http://overwing.ai"), null);
    assert.equal(reportOrigin("file:///etc/passwd"), null);
  });
});

describe("responder: the plan", () => {
  it("turns each target into its rule's command, filling arguments only, and skips what no rule covers", () => {
    const p = plan(webhook(), config(), newMemory(), Date.now());
    assert.ok(p.ok);
    assert.deepEqual(p.steps.map((s) => [s.status, s.rule, s.argv, s.reason]), [
      ["run", "quarantine an IAM user", ["aws", "iam", "put-user-policy", "--user-name", "svc-reports", "--policy-name", "overwing-quarantine", "--policy-document", "file://deny-all.json"], null],
      ["run", "block an address", ["/usr/local/bin/block-ip", "203.0.113.7/32", "--reason=ip:203.0.113.7"], null],
      ["skipped", null, null, "no rule in this responder's config matches"],
    ]);
    assert.equal(p.reportTo, `https://overwing.ai/api/v1/swarm/incidents/${INCIDENT}/responses`);
  });

  it("does nothing when Overwing did not ask, when the incident is below the bar, or when it is not an incident webhook", () => {
    const none = plan(webhook({}, { requested: false }), config(), newMemory(), Date.now());
    assert.ok(none.ok && none.steps.length === 0);
    const high = plan(webhook({ severity: "high" }), config(), newMemory(), Date.now());
    assert.ok(high.ok && high.steps.length === 0);
    const allowed = plan(webhook({ severity: "high" }), config({ min_severity: "high" }), newMemory(), Date.now());
    assert.ok(allowed.ok && allowed.steps.length === 3);
    assert.equal(plan({ type: "evaluation.completed", data: { id: "x" } }, config(), newMemory(), Date.now()).ok, false);
    assert.equal(plan(webhook({ id: "not-an-incident" }), config(), newMemory(), Date.now()).ok, false);
  });

  it("never acts on a protected target, on one that is not a plain name, or on a partial match", () => {
    const actions = (actors: string[]) => ({ requested: true, actions: [{ action: "revoke_identity", surface: null, actors, reason: "r" }], report_to: "" });
    const guarded = plan(webhook({}, actions(["arn:aws:iam::111122223333:user/break-glass"])), config({ protect: [".*:user/break-glass"] }), newMemory(), Date.now());
    assert.ok(guarded.ok);
    assert.deepEqual(guarded.steps.map((s) => [s.status, s.reason]), [["skipped", "protected by this responder's config"]]);
    const odd = plan(webhook({}, actions(["--user-name=admin", "a\nb", "", "x".repeat(301), "arn:aws:iam::111122223333:user/ok; rm -rf /", "prefix arn:aws:iam::111122223333:user/ok"])), config(), newMemory(), Date.now());
    assert.ok(odd.ok);
    assert.ok(odd.steps.every((s) => s.status === "skipped"), JSON.stringify(odd.steps));
  });

  it("acts on a target once for an incident however often the webhook repeats, and stops at the hourly cap", () => {
    const memory = newMemory();
    const c = config();
    const first = plan(webhook(), c, memory, Date.now());
    const again = plan({ ...webhook(), type: "swarm.incident.updated" }, c, memory, Date.now());
    assert.ok(first.ok && again.ok);
    assert.equal(first.steps.filter((s) => s.status === "run").length, 2);
    assert.equal(again.steps.filter((s) => s.status === "run").length, 0);

    const many = { requested: true, actions: [{ action: "block_source", surface: null, actors: Array.from({ length: 6 }, (_, i) => `ip:198.51.100.${i + 1}`), reason: "r" }], report_to: "" };
    const capped = plan(webhook({}, many), config({ max_actions_per_hour: 4 }), newMemory(), Date.now());
    assert.ok(capped.ok);
    assert.deepEqual(capped.steps.map((s) => s.status), ["run", "run", "run", "run", "skipped", "skipped"]);
    assert.match(capped.steps[5]!.reason!, /cap of 4 actions an hour/);
    // An hour later the cap has room again.
    const m = newMemory();
    const t = Date.now();
    plan(webhook({}, many), config({ max_actions_per_hour: 4 }), m, t);
    const later = plan(webhook({ id: "swi_BBBBBBBBBBBBBBBBBBBB" }, many), config({ max_actions_per_hour: 4 }), m, t + 3_600_001);
    assert.ok(later.ok && later.steps.filter((s) => s.status === "run").length === 4);
  });

  it("in dry_run plans the same steps and marks them as not to run, and sends a report only to Overwing's own address", () => {
    const p = plan(webhook(), config({ dry_run: true }), newMemory(), Date.now());
    assert.ok(p.ok);
    assert.deepEqual(p.steps.map((s) => s.status), ["dry_run", "dry_run", "skipped"]);
    const elsewhere = { requested: true, actions: [{ action: "block_source", surface: null, actors: ["ip:203.0.113.7"], reason: "r" }], report_to: "https://attacker.example/collect" };
    const q = plan(webhook({}, elsewhere), config(), newMemory(), Date.now());
    assert.ok(q.ok);
    assert.equal(q.reportTo, `https://overwing.ai/api/v1/swarm/incidents/${INCIDENT}/responses`);
  });
});

describe("responder: end to end", () => {
  it("refuses an unsigned request, runs the rule's command for a signed one, and reports what it did", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const reports: { auth: string | undefined; path: string | undefined; body: Record<string, unknown> }[] = [];
    const overwing = createServer((req, res) => {
      let text = "";
      req.on("data", (c: Buffer) => (text += c.toString()));
      req.on("end", () => {
        reports.push({ auth: req.headers.authorization, path: req.url, body: JSON.parse(text) as Record<string, unknown> });
        res.writeHead(201, { "Content-Type": "application/json" }).end("{}");
      });
    });
    await new Promise<void>((r) => overwing.listen(0, "127.0.0.1", r));
    const overwingUrl = `http://127.0.0.1:${(overwing.address() as AddressInfo).port}`;
    const marker = join(dir, "ran.txt");
    const c = config({
      overwing_url: overwingUrl,
      listen: { host: "127.0.0.1", port: 0 },
      rules: [
        // Stands in for a real command: writes its arguments to a file, with no shell anywhere.
        { name: "mark", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: [process.execPath, "-e", "require('fs').writeFileSync(process.argv[1], process.argv.slice(2).join('|'))", marker, "{1}", "{target}"] },
        { name: "fails", action: "block_source", match: "ip:.+", run: [process.execPath, "-e", "process.stderr.write('no such table'); process.exit(3)"] },
      ],
    });
    const server = serve(c, { secret: SECRET, key: "ow_test_key", name: "test-responder" });
    await new Promise<void>((r) => server.once("listening", () => r()));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    try {
      const body = JSON.stringify(webhook());
      const unsigned = await fetch(url, { method: "POST", body });
      assert.equal(unsigned.status, 401);
      const forged = await fetch(url, { method: "POST", body, headers: { "X-Overwing-Signature": sign(body, undefined, "wrong") } });
      assert.equal(forged.status, 401);
      assert.equal((await fetch(url)).status, 405);

      const ok = await fetch(url, { method: "POST", body, headers: { "X-Overwing-Signature": sign(body) } });
      assert.equal(ok.status, 202);
      assert.deepEqual(await ok.json(), { received: true, incident: INCIDENT, steps: 3 });
      for (let i = 0; i < 100 && reports.length < 3; i++) await new Promise((r) => setTimeout(r, 50));

      assert.equal(await readFile(marker, "utf8"), "svc-reports|arn:aws:iam::111122223333:user/svc-reports");
      assert.equal(reports.length, 3);
      assert.ok(reports.every((r) => r.auth === "Bearer ow_test_key" && r.path === `/api/v1/swarm/incidents/${INCIDENT}/responses`));
      assert.deepEqual(reports.map((r) => [r.body.action, r.body.target, r.body.status, r.body.by]), [
        ["revoke_identity", "arn:aws:iam::111122223333:user/svc-reports", "done", "test-responder"],
        ["block_source", "ip:203.0.113.7", "failed", "test-responder"],
        ["rotate_secrets", "ci-secrets", "skipped", "test-responder"],
      ]);
      assert.match(String(reports[1]!.body.detail), /exit 3: no such table/);
    } finally {
      await new Promise((r) => server.close(r));
      await new Promise((r) => overwing.close(r));
      await rm(dir, { recursive: true, force: true });
    }
  });
});
