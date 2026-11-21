import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadState, saveState, serve, type Serving } from "../src/cli.ts";
import { commandEnv, drain, keyOf, newMemory, plan, readConfig, reportOrigin, verifySignature, type Config, type Memory } from "../src/responder.ts";

// Made up, like every other secret in this file.
const SECRET = "made-up-webhook-secret";
const KEY = "made-up-api-key";
const INCIDENT = "swi_AbCdEfGhIj0123456789";
const OTHER_INCIDENT = "swi_BBBBBBBBBBBBBBBBBBBB";
const user = (name: string): string => `arn:aws:iam::111122223333:user/${name}`;
const USER = user("svc-reports");
const HOUR = 3_600_000;
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

/** A response request for one action: these targets, and, when given, the detectors the action comes from. */
const asks = (action: string, actors: unknown[], more: Record<string, unknown> = {}): Record<string, unknown> => ({ requested: true, actions: [{ action, surface: null, actors, reason: "r", ...more }], report_to: "" });
const planned = (p: ReturnType<typeof plan>): Extract<ReturnType<typeof plan>, { ok: true }> => {
  if (!p.ok) throw new Error(p.error);
  return p;
};

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

  it("keeps its memory in a file beside the config unless told otherwise, and leaves private addresses alone unless told otherwise", () => {
    const c = readConfig({ rules: [] });
    assert.ok(c.ok);
    assert.deepEqual([c.value.state_file, c.value.allow_private_sources, c.value.pass_env], ["overwing-responder-state.json", false, []]);
    const set = readConfig({ rules: [], state_file: "/var/lib/overwing/state.json", allow_private_sources: true, pass_env: ["AWS_PROFILE", "AWS_REGION"] });
    assert.ok(set.ok);
    assert.deepEqual([set.value.state_file, set.value.allow_private_sources, set.value.pass_env], ["/var/lib/overwing/state.json", true, ["AWS_PROFILE", "AWS_REGION"]]);
    const inMemory = readConfig({ rules: [], state_file: null });
    assert.ok(inMemory.ok && inMemory.value.state_file === null);
    for (const state_file of ["", 7, true, ["state.json"]]) assert.equal(readConfig({ rules: [], state_file }).ok, false, JSON.stringify(state_file));
    assert.equal(readConfig({ rules: [], allow_private_sources: "yes" }).ok, false);
  });

  it("refuses a config that would pass the webhook secret or the API key to a command", () => {
    for (const name of ["OVERWING_WEBHOOK_SECRET", "OVERWING_API_KEY", "overwing_api_key", "Overwing_Webhook_Secret"]) {
      const c = readConfig({ rules: [], pass_env: ["AWS_PROFILE", name] });
      assert.ok(!c.ok && /never sees the webhook secret or the API key/.test(c.error), name);
    }
    for (const pass_env of ["AWS_PROFILE", ["AWS PROFILE"], ["A=B"], [7], [""]]) assert.equal(readConfig({ rules: [], pass_env }).ok, false, JSON.stringify(pass_env));
  });

  it("gives a command PATH, HOME, LANG, TZ and what pass_env names, and never the webhook secret or the API key", () => {
    const env = { PATH: "/usr/bin:/bin", HOME: "/home/responder", TZ: "UTC", AWS_PROFILE: "responder", AWS_REGION: undefined, OVERWING_WEBHOOK_SECRET: SECRET, OVERWING_API_KEY: KEY, OVERWING_RESPONDER_NAME: "east", SSH_AUTH_SOCK: "/tmp/agent" };
    assert.deepEqual(commandEnv({ pass_env: ["AWS_PROFILE", "AWS_REGION"] }, env), { PATH: "/usr/bin:/bin", HOME: "/home/responder", TZ: "UTC", AWS_PROFILE: "responder" });
    assert.deepEqual(commandEnv({ pass_env: [] }, env), { PATH: "/usr/bin:/bin", HOME: "/home/responder", TZ: "UTC" });
    // Even for a config that did not come through readConfig.
    assert.deepEqual(commandEnv({ pass_env: ["OVERWING_API_KEY", "OVERWING_WEBHOOK_SECRET"] }, env), { PATH: "/usr/bin:/bin", HOME: "/home/responder", TZ: "UTC" });
  });

  it("refuses a rule whose detectors are not a list of names", () => {
    const rule = { name: "r", action: "revoke_identity", match: ".+", run: ["true"] };
    assert.equal(readConfig({ rules: [{ ...rule, detectors: ["decoy_touch"] }] }).ok, true);
    for (const detectors of [[], "decoy_touch", [7], [""], null]) assert.equal(readConfig({ rules: [{ ...rule, detectors }] }).ok, false, JSON.stringify(detectors));
  });

  it("ships a sample config that is valid, names every field, and answers the sample webhook", async () => {
    const sample = JSON.parse(await readFile(new URL("../sample/config.example.json", import.meta.url), "utf8")) as Record<string, unknown>;
    assert.deepEqual(Object.keys(sample).sort(), ["allow_private_sources", "command_timeout_seconds", "dry_run", "listen", "max_actions_per_hour", "min_severity", "overwing_url", "pass_env", "protect", "rules", "state_file"]);
    const c = readConfig(sample);
    assert.ok(c.ok, c.ok ? "" : c.error);
    assert.ok(c.value.rules.some((r) => r.action === "revoke_identity" && r.detectors?.join() === "decoy_touch"), "a revoke_identity rule limited to decoy_touch");
    const p = planned(plan(JSON.parse(await readFile(new URL("../sample/webhook.example.json", import.meta.url), "utf8")), c.value, newMemory(), Date.now()));
    assert.deepEqual(p.steps.filter((s) => s.status !== "skipped").map((s) => [s.status, s.argv?.slice(0, 5)]), [["dry_run", ["aws", "iam", "put-user-policy", "--user-name", "svc-reports"]]]);
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

  it("takes a severity it does not know as the lowest, even one named like something every object has", () => {
    for (const severity of ["toString", "constructor", "__proto__", "hasOwnProperty", "valueOf", "CRITICAL", "", 3, null]) {
      for (const min_severity of ["critical", "high"]) {
        const p = planned(plan(webhook({ severity }), config({ min_severity }), newMemory(), Date.now()));
        assert.deepEqual(p.steps, [], `${String(severity)} at ${min_severity}`);
      }
    }
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

  it("skips a step when what a target fills would turn an argument into an option, and leaves the rule's own options alone", () => {
    const rules = [{ name: "quarantine", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.*?)(/.*)?", run: ["aws", "iam", "put-user-policy", "--user-name", "{1}", "--note={1}", "--reason={target}", "{2}{1}"] }];
    const memory = newMemory();
    const p = planned(plan(webhook({}, asks("revoke_identity", [user("--help"), user("--policy-arn=arn:aws:iam::aws:policy/AdministratorAccess"), user("-"), user("-x/y"), user("svc-reports")])), config({ rules }), memory, Date.now()));
    assert.deepEqual(p.steps.map((s) => [s.status, s.argv]), [
      ["skipped", null],
      ["skipped", null],
      ["skipped", null],
      ["skipped", null],
      // "--note=" and "--reason=" are the rule's own options: what fills them is their value, whatever it begins with.
      ["run", ["aws", "iam", "put-user-policy", "--user-name", "svc-reports", "--note=svc-reports", `--reason=${user("svc-reports")}`, "svc-reports"]],
    ]);
    for (const s of p.steps.slice(0, 4)) assert.match(String(s.reason), /^rule: quarantine; a filled argument would begin with "-" and be read as an option$/);
    // A step that was skipped used none of the hour's actions and is not remembered as done.
    assert.equal(memory.times.length, 1);
    assert.deepEqual([...memory.done.keys()], [keyOf({ incident: INCIDENT, action: "revoke_identity", target: user("svc-reports") })]);

    // The sample rule's own expression lets a name begin with "-": it is the check on the argument that stops it.
    const sample = planned(plan(webhook({}, asks("revoke_identity", [user("--help")])), config(), newMemory(), Date.now()));
    assert.deepEqual(sample.steps.map((s) => [s.status, s.argv]), [["skipped", null]]);
    // An option the rule wrote itself may take any value.
    const own = planned(plan(webhook({}, asks("revoke_identity", [user("--help")])), config({ rules: [{ name: "own option", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: ["aws", "iam", "put-user-policy", "--user-name={1}", "-{1}"] }] }), newMemory(), Date.now()));
    assert.deepEqual(own.steps.map((s) => [s.status, s.argv]), [["run", ["aws", "iam", "put-user-policy", "--user-name=--help", "---help"]]]);
  });

  it("blocks a source only when the target is one address", () => {
    const rules = [{ name: "block", action: "block_source", match: "ip:(.+)", run: ["/usr/local/bin/block-ip", "{1}"] }];
    const notAddresses = ["ip:0.0.0.0/0", "ip:203.0.113.0/24", "ip:unknown", "ip:", "203.0.113.7", "IP:203.0.113.7", "ip:203.0.113.7,198.51.100.1", "ip:203.0.113.7 ", "ip: 203.0.113.7", "ip:203.0.113", "ip:203.0.113.256", "ip:010.1.1.1", "ip:[2001:db8::7]", "ip:2001:db8::7/64", "ip:example.com", "host:203.0.113.7", "ip:ip:203.0.113.7"];
    const no = planned(plan(webhook({}, asks("block_source", notAddresses)), config({ rules, allow_private_sources: true }), newMemory(), Date.now()));
    assert.deepEqual(no.steps.map((s) => [s.target, s.status, s.reason]), notAddresses.map((t) => [t, "skipped", "not one address: block_source acts only on ip: followed by an IPv4 or IPv6 address"]));
    const addresses = ["ip:203.0.113.7", "ip:198.51.100.200", "ip:2001:db8::7", "ip:2001:DB8:0:0:0:0:0:7", "ip:::ffff:203.0.113.7"];
    const yes = planned(plan(webhook({}, asks("block_source", addresses)), config({ rules }), newMemory(), Date.now()));
    assert.deepEqual(yes.steps.map((s) => [s.status, s.argv]), addresses.map((t) => ["run", ["/usr/local/bin/block-ip", t.slice(3)]]));
    // The rule holds for block_source alone: another action's target is whatever the customer's rule accepts.
    const other = planned(plan(webhook({}, asks("quarantine_surface", ["ip:unknown"])), config({ rules: [{ ...rules[0], action: "quarantine_surface" }] }), newMemory(), Date.now()));
    assert.deepEqual(other.steps.map((s) => s.status), ["run"]);
  });

  it("does not block a private, loopback or unspecified address unless the config allows it", () => {
    const rules = [{ name: "block", action: "block_source", match: "ip:(.+)", run: ["/usr/local/bin/block-ip", "{1}"] }];
    const own = [
      "ip:0.0.0.0", "ip:0.1.2.3", "ip:127.0.0.1", "ip:127.255.255.254",
      "ip:10.0.0.1", "ip:10.255.255.255", "ip:172.16.0.1", "ip:172.31.255.255", "ip:192.168.0.1", "ip:192.168.255.255",
      "ip:169.254.169.254", "ip:100.64.0.1", "ip:100.127.255.255",
      "ip:::", "ip:::1", "ip:0:0:0:0:0:0:0:0", "ip:0:0:0:0:0:0:0:1", "ip:fc00::1", "ip:fd12:3456:789a::1", "ip:FD00::1", "ip:fe80::1", "ip:febf::1", "ip:fec0::1", "ip:feff::1", "ip:fe80::1%eth0",
      "ip:::ffff:10.0.0.1", "ip:::ffff:127.0.0.1", "ip:::ffff:192.168.1.1", "ip:::ffff:a00:1", "ip:0:0:0:0:0:ffff:7f00:1", "ip:::10.0.0.1",
    ];
    const no = planned(plan(webhook({}, asks("block_source", own)), config({ rules }), newMemory(), Date.now()));
    assert.deepEqual(no.steps.map((s) => [s.target, s.status, s.reason]), own.map((t) => [t, "skipped", "a private, loopback or unspecified address, which is likely your own; allow_private_sources is off"]));
    // Just outside each of those ranges is someone else's.
    const outside = ["ip:1.0.0.0", "ip:9.255.255.255", "ip:11.0.0.1", "ip:126.255.255.255", "ip:128.0.0.1", "ip:172.15.255.255", "ip:172.32.0.1", "ip:192.167.255.255", "ip:192.169.0.1", "ip:169.253.0.1", "ip:169.255.0.1", "ip:100.63.255.255", "ip:100.128.0.1", "ip:fbff::1", "ip:fe00::1", "ip:fe7f::1", "ip:2001:db8::1", "ip:::ffff:11.0.0.1", "ip:1::"];
    const yes = planned(plan(webhook({}, asks("block_source", outside)), config({ rules, max_actions_per_hour: 100 }), newMemory(), Date.now()));
    assert.deepEqual(yes.steps.map((s) => [s.target, s.status]), outside.map((t) => [t, "run"]));
    const allowed = planned(plan(webhook({}, asks("block_source", own)), config({ rules, max_actions_per_hour: 100, allow_private_sources: true }), newMemory(), Date.now()));
    assert.deepEqual(allowed.steps.map((s) => [s.target, s.status]), own.map((t) => [t, "run"]));
    // A public address of one's own is for `protect`. The expression the README gives covers both ways it is written there.
    const mine = planned(plan(webhook({}, asks("block_source", ["ip:198.51.100.7", "ip:::ffff:198.51.100.7", "ip:198.51.100.70"])), config({ rules, protect: ["ip:(::ffff:)?198\\.51\\.100\\.7"] }), newMemory(), Date.now()));
    assert.deepEqual(mine.steps.map((s) => [s.status, s.reason]), [["skipped", "protected by this responder's config"], ["skipped", "protected by this responder's config"], ["run", null]]);
  });

  it("lets a rule that names detectors answer only an action that comes from them", () => {
    const decoy = { name: "quarantine on a decoy", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", detectors: ["decoy_touch"], run: ["quarantine", "{1}"] };
    const either = { ...decoy, name: "quarantine on either decoy", detectors: ["decoy_credential", "decoy_touch"] };
    const any = { name: "open a ticket", action: "revoke_identity", match: ".+", run: ["ticket", "{target}"] };
    const answer = (rules: unknown[], more: Record<string, unknown>): unknown[] => planned(plan(webhook({}, asks("revoke_identity", [USER], more)), config({ rules }), newMemory(), Date.now())).steps.map((s) => [s.status, s.rule]);
    const none = [["skipped", null]];
    assert.deepEqual(answer([decoy], { detectors: ["decoy_touch"] }), [["run", "quarantine on a decoy"]]);
    assert.deepEqual(answer([decoy], { detectors: ["sweep"] }), none);
    assert.deepEqual(answer([decoy], { detectors: ["decoy_touch", "sweep"] }), none, "every detector of the action must be in the rule's list");
    assert.deepEqual(answer([decoy], {}), none, "an action that names no detectors is not theirs");
    for (const detectors of [[], null, "decoy_touch", [7], ["decoy_touch", 7], { 0: "decoy_touch" }]) assert.deepEqual(answer([decoy], { detectors }), none, JSON.stringify(detectors));
    assert.deepEqual(answer([either], { detectors: ["decoy_credential"] }), [["run", "quarantine on either decoy"]]);
    assert.deepEqual(answer([either], { detectors: ["decoy_touch", "decoy_credential"] }), [["run", "quarantine on either decoy"]]);
    assert.deepEqual(answer([either], { detectors: ["decoy_touch", "decoy_credential", "sweep"] }), none);
    // First match still wins: what the limited rule leaves is the next rule's, and a rule that names none answers any.
    assert.deepEqual(answer([decoy, any], { detectors: ["decoy_touch"] }), [["run", "quarantine on a decoy"]]);
    assert.deepEqual(answer([decoy, any], { detectors: ["sweep"] }), [["run", "open a ticket"]]);
    assert.deepEqual(answer([decoy, any], {}), [["run", "open a ticket"]]);
  });

  it("acts on a target once for an incident when two actions name it, each from its own detector", () => {
    const decoy = { name: "quarantine on a decoy", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", detectors: ["decoy_touch"], run: ["quarantine", "{1}"] };
    const any = { name: "open a ticket", action: "revoke_identity", match: ".+", run: ["ticket", "{target}"] };
    // As Overwing sends it: one action for each kind of evidence, the strongest first, and an identity can be in both.
    const both = {
      requested: true,
      report_to: "",
      actions: [
        { action: "revoke_identity", surface: null, actors: [user("touched-and-swept"), user("touched")], detectors: ["decoy_touch"], reason: "r" },
        { action: "revoke_identity", surface: null, actors: [user("touched-and-swept"), user("swept")], detectors: ["sweep"], reason: "r" },
      ],
    };
    const now = Date.now();
    const one = planned(plan(webhook({}, both), config({ rules: [decoy] }), newMemory(), now));
    assert.deepEqual(one.steps.map((s) => [s.target, s.status, s.rule ?? s.reason]), [
      [user("touched-and-swept"), "run", "quarantine on a decoy"],
      [user("touched"), "run", "quarantine on a decoy"],
      // The identity in both is not looked at a second time. The one that only swept is nobody's.
      [user("swept"), "skipped", "no rule in this responder's config matches"],
    ]);
    // With a second rule for what the first leaves, each identity is still acted on once: by the first rule to answer it.
    const memory = newMemory();
    const two = planned(plan(webhook({}, both), config({ rules: [decoy, any] }), memory, now));
    assert.deepEqual(two.steps.map((s) => [s.target, s.status, s.rule]), [
      [user("touched-and-swept"), "run", "quarantine on a decoy"],
      [user("touched"), "run", "quarantine on a decoy"],
      [user("swept"), "run", "open a ticket"],
    ]);
    // Once is once for the incident: evidence of another kind, later, does not bring a second rule to the same identity.
    const later = asks("revoke_identity", [user("swept")], { detectors: ["decoy_touch"] });
    assert.deepEqual(planned(plan({ ...webhook({}, later), type: "swarm.incident.updated" }, config({ rules: [decoy, any] }), memory, now + 1000)).steps, []);
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

describe("responder: the queue behind the hourly cap", () => {
  const ips = (n: number): string[] => Array.from({ length: n }, (_, i) => `ip:198.51.100.${i + 1}`);
  const block = (n: string): string[] => ["/usr/local/bin/block-ip", `${n}/32`, `--reason=ip:${n}`];

  it("queues a step over the cap once, and runs it when the cap has room, oldest first", () => {
    const c = config({ max_actions_per_hour: 1 });
    const memory = newMemory();
    const t = Date.now();
    const first = planned(plan(webhook({}, asks("block_source", ips(3))), c, memory, t));
    assert.deepEqual(first.steps.map((s) => [s.status, s.argv]), [["run", block("198.51.100.1")], ["skipped", null], ["skipped", null]]);
    assert.equal(first.steps[1]!.reason, "over this responder's cap of 1 actions an hour; queued to run when the cap has room");
    assert.deepEqual(memory.pending.map((q) => [q.incident, q.target, q.at]), [[INCIDENT, "ip:198.51.100.2", t], [INCIDENT, "ip:198.51.100.3", t]]);
    // The webhook repeats: nothing is queued twice, and nothing is reported twice.
    assert.deepEqual(planned(plan({ ...webhook({}, asks("block_source", ips(3))), type: "swarm.incident.updated" }, c, memory, t + 1000)).steps, []);
    assert.equal(memory.pending.length, 2);
    // Another incident, later, waits behind them.
    planned(plan(webhook({ id: OTHER_INCIDENT }, asks("block_source", ["ip:203.0.113.9"])), c, memory, t + 2000));
    assert.equal(memory.pending.length, 3);

    assert.deepEqual(drain(c, memory, t + HOUR - 1), [], "the first action is not an hour old yet");
    const second = drain(c, memory, t + HOUR);
    assert.deepEqual(second.map((s) => [s.incident, s.target, s.status, s.rule, s.argv, s.at]), [[INCIDENT, "ip:198.51.100.2", "run", "block an address", block("198.51.100.2"), t]]);
    assert.deepEqual(drain(c, memory, t + HOUR + 1), [], "the cap is full again");
    const third = drain(c, memory, t + 2 * HOUR);
    assert.deepEqual(third.map((s) => [s.incident, s.target, s.status]), [[INCIDENT, "ip:198.51.100.3", "run"]]);
    const fourth = drain(c, memory, t + 3 * HOUR);
    assert.deepEqual(fourth.map((s) => [s.incident, s.target, s.status]), [[OTHER_INCIDENT, "ip:203.0.113.9", "run"]]);
    assert.deepEqual(memory.pending, []);
    // Once run, a step is done: the webhook may repeat and the cap may have room, and it does not run again.
    assert.deepEqual(planned(plan(webhook({}, asks("block_source", ips(3))), c, memory, t + 5 * HOUR)).steps, []);
    assert.deepEqual(drain(c, memory, t + 6 * HOUR), []);
  });

  it("runs as many queued steps as the cap has room for, and in dry_run says what it would run", () => {
    const memory = newMemory();
    const t = Date.now();
    planned(plan(webhook({}, asks("block_source", ips(7))), config({ max_actions_per_hour: 3 }), memory, t));
    assert.equal(memory.pending.length, 4);
    const next = drain(config({ max_actions_per_hour: 3, dry_run: true }), memory, t + HOUR + 1);
    assert.deepEqual(next.map((s) => [s.target, s.status]), [["ip:198.51.100.4", "dry_run"], ["ip:198.51.100.5", "dry_run"], ["ip:198.51.100.6", "dry_run"]]);
    assert.deepEqual(memory.pending.map((q) => q.target), ["ip:198.51.100.7"]);
  });

  it("does not run a step that waited more than 24 hours, and says so", () => {
    const c = config({ max_actions_per_hour: 1 });
    const t = Date.now();
    const queue = (): Memory => {
      const memory = newMemory();
      planned(plan(webhook({}, asks("block_source", ips(3))), c, memory, t));
      return memory;
    };
    // At 24 hours a step is still run.
    const inTime = queue();
    assert.deepEqual(drain(c, inTime, t + 24 * HOUR).map((s) => [s.target, s.status]), [["ip:198.51.100.2", "run"]]);
    // A millisecond past, it is not, though the cap has room. It is reported as skipped, with the reason.
    const late = queue();
    const steps = drain(c, late, t + 24 * HOUR + 1);
    assert.deepEqual(steps.map((s) => [s.incident, s.target, s.status, s.argv, s.reason]), [
      [INCIDENT, "ip:198.51.100.2", "skipped", null, "queued for more than 24 hours behind this responder's hourly cap: not run"],
      [INCIDENT, "ip:198.51.100.3", "skipped", null, "queued for more than 24 hours behind this responder's hourly cap: not run"],
    ]);
    assert.deepEqual([late.pending, late.times], [[], []], "nothing is left queued, and nothing was counted against the cap");
  });

  it("holds a queued step to the config of the moment it runs", () => {
    const memory = newMemory();
    const t = Date.now();
    planned(plan(webhook({}, asks("block_source", ips(4))), config({ max_actions_per_hour: 1 }), memory, t));
    // By the time the cap has room, the config protects one target and has no rule for the action of another incident.
    const stricter = config({ max_actions_per_hour: 1, protect: ["ip:198\\.51\\.100\\.2"] });
    assert.deepEqual(drain(stricter, memory, t + HOUR + 1).map((s) => [s.target, s.status, s.reason]), [
      ["ip:198.51.100.2", "skipped", "protected by this responder's config"],
      ["ip:198.51.100.3", "run", null],
    ]);
    const noRule = config({ max_actions_per_hour: 1, rules: [] });
    assert.deepEqual(drain(noRule, memory, t + 2 * HOUR + 2).map((s) => [s.target, s.status, s.reason]), [["ip:198.51.100.4", "skipped", "no rule in this responder's config matches"]]);
    assert.deepEqual(memory.pending, []);
  });

  it("stops queueing when the queue is full", () => {
    const c = config({ max_actions_per_hour: 1, rules: [{ name: "block", action: "block_source", match: "ip:(.+)", run: ["/usr/local/bin/block-ip", "{1}"] }] });
    const memory = newMemory();
    const t = Date.now();
    // Six webhooks of 200 addresses each: one runs, 1,000 wait, and the rest are turned away.
    for (let w = 0; w < 6; w++) planned(plan(webhook({}, asks("block_source", Array.from({ length: 200 }, (_, i) => `ip:2001:db8::${(w * 200 + i + 1).toString(16)}`))), c, memory, t));
    assert.equal(memory.pending.length, 1000);
    const more = planned(plan(webhook({}, asks("block_source", ["ip:203.0.113.9"])), c, memory, t));
    assert.deepEqual(more.steps.map((s) => [s.status, s.reason]), [["skipped", "over this responder's cap of 1 actions an hour, and 1000 steps already wait: not queued"]]);
    assert.equal(memory.pending.length, 1000);
  });
});

describe("responder: the state file", () => {
  const within = async (run: (dir: string) => Promise<void>): Promise<void> => {
    const dir = await mkdtemp(join(tmpdir(), "responder-state-"));
    try {
      await run(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };
  const three = asks("block_source", ["ip:198.51.100.1", "ip:198.51.100.2", "ip:198.51.100.3"], { detectors: ["decoy_credential"] });

  it("keeps what was acted on, the hour's actions and the queue, and reads them back", () =>
    within(async (dir) => {
      const file = join(dir, "state.json");
      const c = config({ max_actions_per_hour: 2 });
      const memory = newMemory();
      const t = Date.now();
      planned(plan(webhook({}, three), c, memory, t));
      saveState(file, memory, t);
      const back = loadState(file);
      assert.deepEqual([...back.done], [[keyOf({ incident: INCIDENT, action: "block_source", target: "ip:198.51.100.1" }), t], [keyOf({ incident: INCIDENT, action: "block_source", target: "ip:198.51.100.2" }), t]]);
      assert.deepEqual(back.times, [t, t]);
      assert.deepEqual(back.pending, [{ incident: INCIDENT, action: "block_source", target: "ip:198.51.100.3", detectors: ["decoy_credential"], at: t }]);
      // What was read back is what the responder knew: the webhook again leads to nothing, and the queue is run later.
      assert.deepEqual(planned(plan(webhook({}, three), c, back, t + 1000)).steps, []);
      assert.deepEqual(drain(c, back, t + HOUR + 1).map((s) => [s.target, s.status]), [["ip:198.51.100.3", "run"]]);
    }));

  it("holds what was asked and never a command: what runs is decided from the config, whatever the file says", () =>
    within(async (dir) => {
      const file = join(dir, "state.json");
      const c = config({ max_actions_per_hour: 2 });
      const memory = newMemory();
      const t = Date.now();
      planned(plan(webhook({}, three), c, memory, t));
      saveState(file, memory, t);
      const text = await readFile(file, "utf8");
      assert.ok(!text.includes("block-ip") && !text.includes("argv") && !text.includes("rule"), text);
      // Someone who can write the file adds a command to a queued step. It is not read, and is not run.
      const edited = JSON.parse(text) as { pending: Record<string, unknown>[] };
      edited.pending[0] = { ...edited.pending[0], rule: "theirs", argv: ["/bin/sh", "-c", "id"], run: ["/bin/sh", "-c", "id"], status: "run" };
      await writeFile(file, JSON.stringify(edited));
      const back = loadState(file);
      assert.deepEqual(back.pending, [{ incident: INCIDENT, action: "block_source", target: "ip:198.51.100.3", detectors: ["decoy_credential"], at: t }]);
      assert.deepEqual(drain(c, back, t + HOUR + 1).map((s) => [s.rule, s.argv]), [["block an address", ["/usr/local/bin/block-ip", "198.51.100.3/32", "--reason=ip:198.51.100.3"]]]);
    }));

  it("writes the file whole, as a new file renamed over the old one, for this user only", { skip: process.platform === "win32" }, () =>
    within(async (dir) => {
      const file = join(dir, "state.json");
      const memory = newMemory();
      const t = Date.now();
      saveState(file, memory, t);
      const first = await stat(file);
      assert.equal(first.mode & 0o777, 0o600);
      // Whatever the file was before, a save leaves a file only this user can read.
      await chmod(file, 0o644);
      planned(plan(webhook(), config(), memory, t));
      saveState(file, memory, t);
      const second = await stat(file);
      assert.equal(second.mode & 0o777, 0o600);
      assert.notEqual(second.ino, first.ino, "the old file was replaced by a rename, not written into");
      assert.deepEqual(await readdir(dir), ["state.json"], "no temporary file is left");
      assert.equal(loadState(file).done.size, 2);
    }));

  it("leaves the old state and no temporary file when a save fails", () =>
    within(async (dir) => {
      // A directory stands where the file should be, so the rename cannot happen.
      const file = join(dir, "state.json");
      await mkdir(join(file, "in-the-way"), { recursive: true });
      assert.throws(() => saveState(file, newMemory(), Date.now()));
      assert.deepEqual(await readdir(dir), ["state.json"]);
      assert.deepEqual(await readdir(file), ["in-the-way"]);
      assert.throws(() => saveState(join(dir, "no-such-directory", "state.json"), newMemory(), Date.now()));
    }));

  it("drops what was acted on more than seven days ago when it saves, and actions over an hour old", () =>
    within(async (dir) => {
      const file = join(dir, "state.json");
      const now = Date.now();
      const day = 24 * HOUR;
      const old = keyOf({ incident: INCIDENT, action: "revoke_identity", target: USER });
      const edge = keyOf({ incident: INCIDENT, action: "block_source", target: "ip:203.0.113.7" });
      const recent = keyOf({ incident: OTHER_INCIDENT, action: "revoke_identity", target: USER });
      const memory = newMemory();
      memory.done.set(old, now - 7 * day - 1);
      memory.done.set(edge, now - 7 * day);
      memory.done.set(recent, now - 1000);
      memory.times.push(now - HOUR - 1, now - HOUR + 1, now - 1000);
      saveState(file, memory, now);
      const back = loadState(file);
      assert.deepEqual([...back.done], [[edge, now - 7 * day], [recent, now - 1000]]);
      assert.deepEqual(back.times, [now - HOUR + 1, now - 1000]);
      assert.deepEqual([...memory.done.keys()], [edge, recent], "the running responder forgets it too");
    }));

  it("takes a missing file as an empty memory, and refuses a corrupt one", () =>
    within(async (dir) => {
      const file = join(dir, "state.json");
      assert.deepEqual(loadState(file), newMemory());
      const entry = { incident: INCIDENT, action: "revoke_identity" as const, target: USER, at: 1 };
      const state = (over: Record<string, unknown>): string => JSON.stringify({ version: 1, done: [], times: [], pending: [], ...over });
      const corrupt = [
        "",
        "{",
        '{"version":1,"done":[],"times":[],"pending":[',
        "null",
        "[]",
        "{}",
        state({ version: 2 }),
        state({ done: undefined }),
        state({ times: {} }),
        state({ pending: "none" }),
        state({ done: [{ ...entry, incident: "not-an-incident" }] }),
        state({ done: [{ ...entry, at: "yesterday" }] }),
        state({ done: [null] }),
        state({ times: ["now"] }),
        state({ times: [-1] }),
        state({ pending: [{ ...entry, action: "run_anything" }] }),
        state({ pending: [{ ...entry, target: "--help" }] }),
        state({ pending: [{ ...entry, target: "a\nb" }] }),
        state({ pending: [{ ...entry, detectors: "decoy_touch" }] }),
      ];
      for (const text of corrupt) {
        await writeFile(file, text);
        assert.throws(() => loadState(file), (e: Error) => e.message.includes(file) && /is corrupt: .+ Not starting/.test(e.message), text);
        assert.equal(await readFile(file, "utf8"), text, "a file that was not understood is left as it was found");
      }
      await writeFile(file, state({ done: [entry], times: [5], pending: [{ ...entry, incident: OTHER_INCIDENT, detectors: ["sweep"] }] }));
      const back = loadState(file);
      assert.deepEqual([[...back.done], back.times, back.pending], [[[keyOf(entry), 1]], [5], [{ ...entry, incident: OTHER_INCIDENT, detectors: ["sweep"] }]]);
    }));
});

type Report = { auth: string | undefined; path: string | undefined; body: Record<string, unknown> };

/** Stands in for Overwing, on this machine: keeps the reports it is sent. */
async function overwingStub(): Promise<{ url: string; reports: Report[]; close: () => Promise<void> }> {
  const reports: Report[] = [];
  const server = createServer((req, res) => {
    let text = "";
    req.on("data", (c: Buffer) => (text += c.toString()));
    req.on("end", () => {
      reports.push({ auth: req.headers.authorization, path: req.url, body: JSON.parse(text) as Record<string, unknown> });
      res.writeHead(201, { "Content-Type": "application/json" }).end("{}");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  // Not a reason to keep the test run alive, should a test end before it closes this.
  server.unref();
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, reports, close: () => new Promise((r) => server.close(() => r())) };
}

type Responder = { url: string; stop: () => Promise<void> };

/** Starts a responder on a free port of this machine. */
async function start(c: Config, memory: Memory = newMemory(), serving: Serving = {}): Promise<Responder> {
  const server = serve(c, { secret: SECRET, key: KEY, name: "test-responder" }, memory, serving);
  await new Promise<void>((r) => server.once("listening", () => r()));
  server.unref();
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`, stop: () => new Promise((r) => server.close(() => r())) };
}

const post = (url: string, body: string, signature: string = sign(body)): Promise<Response> => fetch(url, { method: "POST", body, headers: { "X-Overwing-Signature": signature } });
const until = async (done: () => boolean | Promise<boolean>, ms = 10_000): Promise<void> => {
  for (let waited = 0; waited < ms && !(await done()); waited += 20) await new Promise((r) => setTimeout(r, 20));
};
const text = (file: string): Promise<string> => readFile(file, "utf8").catch(() => "");
/** Stands in for a real command: adds its last argument to a file as a line, with no shell anywhere. */
const append = (file: string, ...args: string[]): string[] => [process.execPath, "-e", "require('fs').appendFileSync(process.argv[1], process.argv[process.argv.length - 1] + '\\n')", file, ...args];
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
    const server = serve(c, { secret: SECRET, key: KEY, name: "test-responder" });
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
      assert.ok(reports.every((r) => r.auth === `Bearer ${KEY}` && r.path === `/api/v1/swarm/incidents/${INCIDENT}/responses`));
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

  it("runs a command without the webhook secret and the API key in its environment, and with what pass_env names", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const seen = join(dir, "env.json");
    // The responder itself has both secrets in its environment, as it does when it serves.
    const set: Record<string, string> = { OVERWING_WEBHOOK_SECRET: SECRET, OVERWING_API_KEY: KEY, RESPONDER_TEST_PASSED: "listed in pass_env", RESPONDER_TEST_KEPT: "not listed" };
    const before = Object.fromEntries(Object.keys(set).map((k) => [k, process.env[k]]));
    Object.assign(process.env, set);
    const overwing = await overwingStub();
    const c = config({
      overwing_url: overwing.url,
      listen: { host: "127.0.0.1", port: 0 },
      pass_env: ["RESPONDER_TEST_PASSED", "RESPONDER_TEST_NOT_SET"],
      rules: [{ name: "show", action: "revoke_identity", match: ".+", run: [process.execPath, "-e", "require('fs').writeFileSync(process.argv[1], JSON.stringify(process.env))", seen] }],
    });
    const responder = await start(c);
    try {
      const body = JSON.stringify(webhook({}, asks("revoke_identity", [USER])));
      assert.equal((await post(responder.url, body)).status, 202);
      await until(() => overwing.reports.length === 1);
      assert.deepEqual(overwing.reports.map((r) => [r.body.status, r.body.detail]), [["done", "rule: show; exit 0"]]);
      const env = JSON.parse(await readFile(seen, "utf8")) as Record<string, string>;
      assert.deepEqual(Object.keys(env).filter((k) => /overwing/i.test(k)), []);
      assert.ok(!JSON.stringify(env).includes(SECRET) && !JSON.stringify(env).includes(KEY));
      assert.equal(env.RESPONDER_TEST_PASSED, "listed in pass_env");
      assert.ok(!("RESPONDER_TEST_KEPT" in env) && !("RESPONDER_TEST_NOT_SET" in env));
      for (const name of ["PATH", "HOME", "LANG", "TZ"]) assert.equal(env[name], process.env[name], name);
      // The report still carries the key: it is the responder that sends it, not the command.
      assert.equal(overwing.reports[0]!.auth, `Bearer ${KEY}`);
    } finally {
      for (const [k, v] of Object.entries(before)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      await responder.stop();
      await overwing.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("accepts a webhook that names 200 long identities under each action, and refuses one over 1 MB", async () => {
    const c = config({ listen: { host: "127.0.0.1", port: 0 }, rules: [] });
    const responder = await start(c);
    try {
      const actors = Array.from({ length: 200 }, (_, i) => `arn:aws:sts::111122223333:assumed-role/${"r".repeat(120)}/${String(i).padStart(4, "0")}${"s".repeat(120)}`);
      const actions = ["revoke_identity", "block_source", "rotate_secrets", "quarantine_surface"].map((action) => ({ action, surface: null, actors, reason: "r" }));
      // Below min_severity, so this is about the size alone: nothing is planned for it.
      const large = JSON.stringify(webhook({ severity: "high", actors, recommended_actions: actions }, { requested: true, actions, report_to: "" }));
      assert.ok(large.length > 256 * 1024 && large.length < 1024 * 1024, String(large.length));
      const ok = await post(responder.url, large);
      assert.equal(ok.status, 202);
      assert.deepEqual(await ok.json(), { received: true, incident: INCIDENT, steps: 0 });

      const tooLarge = JSON.stringify(webhook({ severity: "high", title: "t".repeat(1024 * 1024) }));
      // The responder stops reading and closes the connection, so the sender sees a 413 or a closed connection.
      const refused = await post(responder.url, tooLarge).then((r) => r.status, () => "closed");
      assert.ok(refused === 413 || refused === "closed", String(refused));
      const after = await post(responder.url, JSON.stringify(webhook({ severity: "high" })));
      assert.equal(after.status, 202, "and goes on serving");
    } finally {
      await responder.stop();
    }
  });

  it("after a restart does not run a replayed webhook again, still counts the hour's actions, and still holds the queue", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const stateFile = join(dir, "state.json");
    const ran = join(dir, "ran.txt");
    const overwing = await overwingStub();
    const c = config({ overwing_url: overwing.url, listen: { host: "127.0.0.1", port: 0 }, max_actions_per_hour: 1, rules: [{ name: "mark", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: append(ran, "{1}") }] });
    const body = JSON.stringify(webhook({}, asks("revoke_identity", [user("svc-reports")])));
    const signature = sign(body);
    let ahead = 0;
    const serving: Serving = { stateFile, tickMs: 20, now: () => Date.now() + ahead };
    let responder: Responder | undefined;
    try {
      responder = await start(c, loadState(stateFile), serving);
      assert.equal((await post(responder.url, body, signature)).status, 202);
      await until(() => overwing.reports.length === 1);
      assert.equal(await text(ran), "svc-reports\n");
      await responder.stop();

      // A new process knows only what the file holds.
      responder = await start(c, loadState(stateFile), serving);
      const replayed = await post(responder.url, body, signature);
      assert.equal(replayed.status, 202);
      assert.deepEqual(await replayed.json(), { received: true, incident: INCIDENT, steps: 0 });
      // Another incident: the one action this hour allows was used before the restart, so this one waits.
      assert.equal((await post(responder.url, JSON.stringify(webhook({ id: OTHER_INCIDENT }, asks("revoke_identity", [user("svc-build")]))))).status, 202);
      await until(() => overwing.reports.length === 2);
      assert.deepEqual(overwing.reports.map((r) => [r.path, r.body.target, r.body.status, r.body.detail]), [
        [`/api/v1/swarm/incidents/${INCIDENT}/responses`, user("svc-reports"), "done", "rule: mark; exit 0"],
        [`/api/v1/swarm/incidents/${OTHER_INCIDENT}/responses`, user("svc-build"), "skipped", "over this responder's cap of 1 actions an hour; queued to run when the cap has room"],
      ]);
      assert.equal(await text(ran), "svc-reports\n", "the replay ran nothing");
      await responder.stop();

      // A third process finds the queued step in the file, and runs it once the hour has passed.
      responder = await start(c, loadState(stateFile), serving);
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(overwing.reports.length, 2, "not before the cap has room");
      ahead = HOUR + 1;
      await until(() => overwing.reports.length === 3);
      assert.deepEqual([overwing.reports[2]!.path, overwing.reports[2]!.body.target, overwing.reports[2]!.body.status], [`/api/v1/swarm/incidents/${OTHER_INCIDENT}/responses`, user("svc-build"), "done"]);
      assert.equal(await text(ran), "svc-reports\nsvc-build\n");
      const state = loadState(stateFile);
      assert.deepEqual([state.done.size, state.pending], [2, []]);
    } finally {
      await responder?.stop();
      await overwing.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("runs a step that waited for the hourly cap when the cap has room, and reports it then", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const ran = join(dir, "ran.txt");
    const overwing = await overwingStub();
    const c = config({ overwing_url: overwing.url, listen: { host: "127.0.0.1", port: 0 }, max_actions_per_hour: 1, rules: [{ name: "mark", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: append(ran, "{1}") }] });
    let ahead = 0;
    // The cap is looked at every 20 ms here, once a minute when serving for real.
    const responder = await start(c, newMemory(), { tickMs: 20, now: () => Date.now() + ahead });
    try {
      const body = JSON.stringify(webhook({}, asks("revoke_identity", [user("first"), user("second"), user("third")])));
      assert.equal((await post(responder.url, body)).status, 202);
      await until(() => overwing.reports.length === 3);
      const queued = "over this responder's cap of 1 actions an hour; queued to run when the cap has room";
      assert.deepEqual(overwing.reports.map((r) => [r.body.target, r.body.status, r.body.detail]), [[user("first"), "done", "rule: mark; exit 0"], [user("second"), "skipped", queued], [user("third"), "skipped", queued]]);
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(await text(ran), "first\n", "nothing more while the cap is full");
      assert.equal(overwing.reports.length, 3);

      ahead = HOUR + 1;
      await until(() => overwing.reports.length === 4);
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(await text(ran), "first\nsecond\n", "one more, and the oldest first");
      assert.deepEqual(overwing.reports.slice(3).map((r) => [r.path, r.body.target, r.body.status, r.body.detail]), [[`/api/v1/swarm/incidents/${INCIDENT}/responses`, user("second"), "done", "rule: mark; exit 0"]]);

      // A day after it was asked for, the last one is not run. It is reported as skipped, with the reason.
      ahead = 24 * HOUR + 1;
      await until(() => overwing.reports.length === 5);
      assert.deepEqual(overwing.reports.slice(4).map((r) => [r.body.target, r.body.status, r.body.detail]), [[user("third"), "skipped", "queued for more than 24 hours behind this responder's hourly cap: not run"]]);
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(await text(ran), "first\nsecond\n");
    } finally {
      await responder.stop();
      await overwing.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps a step that was decided and has not started as queued in the state file, so a restart runs it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const stateFile = join(dir, "state.json");
    const ran = join(dir, "ran.txt");
    const go = join(dir, "go");
    const overwing = await overwingStub();
    // Stands in for a slow command: notes its target, then waits until the file `go` exists.
    const slow = [process.execPath, "-e", "const fs = require('fs'); fs.appendFileSync(process.argv[1], process.argv[3] + '\\n'); const t = setInterval(() => { if (fs.existsSync(process.argv[2])) clearInterval(t); }, 10);", ran, go, "{1}"];
    const c = config({ overwing_url: overwing.url, listen: { host: "127.0.0.1", port: 0 }, rules: [{ name: "slow", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: slow }] });
    const targets = async (): Promise<{ done: string[]; pending: string[] }> => {
      const state = JSON.parse(await readFile(stateFile, "utf8")) as { done: { target: string }[]; pending: { target: string }[] };
      return { done: state.done.map((d) => d.target), pending: state.pending.map((p) => p.target) };
    };
    let responder: Responder | undefined;
    try {
      responder = await start(c, loadState(stateFile), { stateFile });
      assert.equal((await post(responder.url, JSON.stringify(webhook({}, asks("revoke_identity", [user("first"), user("second")]))))).status, 202);
      await until(async () => (await text(ran)) === "first\n");
      // The first command is running. If the responder stopped now, the second would not have been started.
      assert.deepEqual(await targets(), { done: [user("first")], pending: [user("second")] });
      const restarted = loadState(stateFile);
      assert.deepEqual(drain(c, restarted, Date.now()).map((s) => [s.target, s.status]), [[user("second"), "run"]], "a restart would run it");
      assert.deepEqual(drain(c, restarted, Date.now()), [], "once");

      await writeFile(go, "");
      await until(() => overwing.reports.length === 2);
      assert.deepEqual(overwing.reports.map((r) => [r.body.target, r.body.status]), [[user("first"), "done"], [user("second"), "done"]]);
      assert.equal(await text(ran), "first\nsecond\n");
      assert.deepEqual(await targets(), { done: [user("first"), user("second")], pending: [] });
    } finally {
      await writeFile(go, "");
      await responder?.stop();
      await overwing.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("in dry_run reads the state file and adds nothing to it, so a rehearsal does not stand in for the real run", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const stateFile = join(dir, "state.json");
    const ran = join(dir, "ran.txt");
    const overwing = await overwingStub();
    const base = { overwing_url: overwing.url, listen: { host: "127.0.0.1", port: 0 }, max_actions_per_hour: 1, rules: [{ name: "mark", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: append(ran, "{1}") }] };
    const body = JSON.stringify(webhook({}, asks("revoke_identity", [user("svc-reports")])));
    let responder: Responder | undefined;
    try {
      responder = await start(config({ ...base, dry_run: true }), loadState(stateFile), { stateFile });
      assert.equal((await post(responder.url, body)).status, 202);
      await until(() => overwing.reports.length === 1);
      assert.deepEqual(overwing.reports.map((r) => [r.body.status, r.body.detail]), [["dry_run", "rule: mark"]]);
      assert.equal(await text(stateFile), "", "the rehearsal left no mark");
      await responder.stop();

      // dry_run is turned off. The rehearsal does not count as done, and did not use the one action this hour allows.
      responder = await start(config(base), loadState(stateFile), { stateFile });
      assert.equal((await post(responder.url, body)).status, 202);
      await until(() => overwing.reports.length === 2);
      assert.deepEqual(overwing.reports.slice(1).map((r) => [r.body.status, r.body.detail]), [["done", "rule: mark; exit 0"]]);
      assert.equal(await text(ran), "svc-reports\n");
      await responder.stop();

      // A rehearsal after that knows what was really done, and still writes nothing.
      const before = await text(stateFile);
      responder = await start(config({ ...base, dry_run: true }), loadState(stateFile), { stateFile });
      const again = await post(responder.url, body);
      assert.deepEqual(await again.json(), { received: true, incident: INCIDENT, steps: 0 });
      assert.equal((await post(responder.url, JSON.stringify(webhook({ id: OTHER_INCIDENT }, asks("revoke_identity", [user("svc-build")]))))).status, 202);
      await until(() => overwing.reports.length === 3);
      assert.match(String(overwing.reports[2]!.body.detail), /cap of 1 actions an hour; queued/, "the action really taken this hour counts in the rehearsal");
      assert.equal(await text(stateFile), before);
    } finally {
      await responder?.stop();
      await overwing.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("gives a command command_timeout_seconds to finish, and reports one that does not as failed", async () => {
    const overwing = await overwingStub();
    const c = config({ overwing_url: overwing.url, listen: { host: "127.0.0.1", port: 0 }, command_timeout_seconds: 1, rules: [{ name: "hangs", action: "revoke_identity", match: ".+", run: [process.execPath, "-e", "setTimeout(() => undefined, 60000)"] }] });
    const responder = await start(c);
    try {
      assert.equal((await post(responder.url, JSON.stringify(webhook({}, asks("revoke_identity", [USER]))))).status, 202);
      await until(() => overwing.reports.length === 1);
      assert.deepEqual(overwing.reports.map((r) => r.body.status), ["failed"]);
      assert.match(String(overwing.reports[0]!.body.detail), /^rule: hangs; timed out/);
    } finally {
      await responder.stop();
      await overwing.close();
    }
  });

  it("reports a command that could not be started as failed, and goes on to the next step", async () => {
    const dir = await mkdtemp(join(tmpdir(), "responder-"));
    const ran = join(dir, "ran.txt");
    const overwing = await overwingStub();
    const c = config({
      overwing_url: overwing.url,
      listen: { host: "127.0.0.1", port: 0 },
      rules: [
        // No program can be given an argument with a NUL in it.
        { name: "cannot start", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/broken", run: [process.execPath, "a\u0000b"] },
        { name: "mark", action: "revoke_identity", match: "arn:aws:iam::\\d{12}:user/(.+)", run: append(ran, "{1}") },
      ],
    });
    const responder = await start(c);
    try {
      assert.equal((await post(responder.url, JSON.stringify(webhook({}, asks("revoke_identity", [user("broken"), user("svc-reports")]))))).status, 202);
      await until(() => overwing.reports.length === 2);
      assert.deepEqual(overwing.reports.map((r) => [r.body.target, r.body.status]), [[user("broken"), "failed"], [user("svc-reports"), "done"]]);
      assert.match(String(overwing.reports[0]!.body.detail), /^rule: cannot start; not started: /);
      assert.equal(await text(ran), "svc-reports\n");
    } finally {
      await responder.stop();
      await overwing.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("responder: the command line", () => {
  const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const cli = (args: string[], env: Record<string, string> = {}): Promise<{ code: number | string | null; stdout: string; stderr: string }> =>
    new Promise((resolve) => {
      execFile(process.execPath, [CLI, ...args], { env: { ...process.env, ...env }, timeout: 30_000 }, (err, stdout, stderr) => resolve({ code: err ? ((err as { code?: number | string | null }).code ?? null) : 0, stdout, stderr }));
    });
  const within = async (run: (dir: string, configFile: string) => Promise<void>, over: Record<string, unknown> = {}): Promise<void> => {
    const dir = await mkdtemp(join(tmpdir(), "responder-cli-"));
    try {
      await writeFile(join(dir, "config.json"), JSON.stringify({ listen: { host: "127.0.0.1", port: 0 }, rules: [], ...over }));
      await run(dir, join(dir, "config.json"));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it("check says where the memory is kept: beside the config by default, or nowhere, with what that costs", async () => {
    await within(async (dir, configFile) => {
      const r = await cli(["check", "--config", configFile]);
      assert.equal(r.code, 0, r.stderr);
      assert.ok(r.stdout.includes(`Keeps its memory in ${join(dir, "overwing-responder-state.json")}. While dry_run is on it reads that file and adds nothing to it.`), r.stdout);
      assert.deepEqual(await readdir(dir), ["config.json"], "check writes nothing");
    });
    await within(async (dir, configFile) => {
      const r = await cli(["check", "--config", configFile]);
      assert.ok(r.stdout.includes(`Keeps its memory in ${join(dir, "overwing-responder-state.json")}.\n`), r.stdout);
    }, { dry_run: false });
    await within(async (dir, configFile) => {
      const r = await cli(["check", "--config", configFile]);
      assert.ok(r.stdout.includes(`Keeps its memory in ${join(dir, "kept", "state.json")}.`), r.stdout);
    }, { state_file: "kept/state.json" });
    await within(async (_dir, configFile) => {
      const r = await cli(["check", "--config", configFile]);
      assert.equal(r.code, 0, r.stderr);
      assert.match(r.stdout, /state_file is null: the memory is kept in the process only\. After a restart, a webhook replayed within five minutes runs again/);
    }, { state_file: null });
    await within(async (_dir, configFile) => {
      const r = await cli(["check", "--config", configFile]);
      assert.equal(r.code, 1);
      assert.match(r.stderr, /pass_env may not name OVERWING_API_KEY/);
    }, { pass_env: ["OVERWING_API_KEY"] });
  });

  it("serve does not start on a corrupt state file, and leaves the file as it found it", async () => {
    await within(async (dir, configFile) => {
      const stateFile = join(dir, "overwing-responder-state.json");
      await writeFile(stateFile, '{"version":1,"done":[');
      const r = await cli(["serve", "--config", configFile], { OVERWING_WEBHOOK_SECRET: SECRET });
      assert.equal(r.code, 1, `${r.stdout}\n${r.stderr}`);
      assert.ok(r.stderr.includes(`The state file ${stateFile} is corrupt: it is not JSON. Not starting`), r.stderr);
      assert.equal(await readFile(stateFile, "utf8"), '{"version":1,"done":[');
    });
  });

  it("serve does not start when the state file cannot be written", async () => {
    await within(async (dir, configFile) => {
      const r = await cli(["serve", "--config", configFile], { OVERWING_WEBHOOK_SECRET: SECRET });
      assert.equal(r.code, 1, `${r.stdout}\n${r.stderr}`);
      assert.ok(r.stderr.includes(`Could not write the state file ${join(dir, "no-such-directory", "state.json")}`), r.stderr);
    }, { state_file: "no-such-directory/state.json" });
  });

  it("serve starts with an empty memory when there is no state file yet, and writes one only this user can read", { skip: process.platform === "win32" }, async () => {
    await within(async (dir, configFile) => {
      const child = spawn(process.execPath, [CLI, "serve", "--config", configFile], { env: { ...process.env, OVERWING_WEBHOOK_SECRET: SECRET }, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (c: Buffer) => (out += c.toString()));
      child.stderr.on("data", (c: Buffer) => (out += c.toString()));
      const exited = new Promise<number | null>((r) => child.once("exit", (code) => r(code)));
      try {
        await until(() => out.includes("wait for the hourly cap") || child.exitCode !== null, 30_000);
        assert.ok(out.includes("Remembers 0 targets acted on in the last seven days; 0 steps wait for the hourly cap."), out);
        const stateFile = join(dir, "overwing-responder-state.json");
        assert.deepEqual(JSON.parse(await readFile(stateFile, "utf8")), { version: 1, done: [], times: [], pending: [] });
        assert.equal((await stat(stateFile)).mode & 0o777, 0o600);
      } finally {
        child.kill("SIGTERM");
        await exited;
      }
    });
  });
});
