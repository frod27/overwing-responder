# overwing-responder

Carries out, on your side and with your own credentials, what an
[Overwing Radar](https://overwing.ai/radar) incident asks for: disable an identity, block an
address. A signed webhook comes in, one of your own commands runs, and a report goes back so the
incident shows how long containment took.

Overwing never holds your credentials and never runs anything on your systems. It asks, in the
webhook, and only when you have switched the response step on for your account. This program is
what answers. It runs inside your environment, so the whole of it is here to read before you run
it: two files, no dependencies.

The guide is [Radar against an intrusion run by agents](https://overwing.ai/radar/intrusion-response).

## Get it

With Node 22.18 or later (the sources run as they are; there is no build step):

```
git clone https://github.com/frod27/overwing-responder
cd overwing-responder
cp sample/config.example.json config.json      # then make the rules yours
node src/cli.ts check --config config.json
```

## Run it

```
node src/cli.ts test  --config config.json --webhook sample/webhook.example.json   # what a webhook would lead to; runs nothing
OVERWING_WEBHOOK_SECRET=... OVERWING_API_KEY=... node src/cli.ts serve --config config.json
```

- `OVERWING_WEBHOOK_SECRET`: the secret of your Overwing webhook. Required. A request whose
  signature does not match it is refused.
- `OVERWING_API_KEY`: used only to report back what was done. Make a key of scope `respond` for it: that key can report on incidents and do nothing else. The key that sends events (`swarm`) cannot report, because it sits where an intruder would find it.
  Without it the responder acts and logs, and reports nothing.
- `OVERWING_RESPONDER_NAME`: a name for this responder in the reports.

The secret and the key are for the responder alone. A command it runs is never given them.

It listens on `127.0.0.1:8790` unless the config says otherwise. Put it behind whatever already
terminates TLS for you, and set your Overwing webhook to that address. Then switch the response
step on:

```
curl -X PUT https://overwing.ai/api/v1/swarm/config \
  -H "Authorization: Bearer $OVERWING_API_KEY" -H "Content-Type: application/json" \
  -d '{"response": {"enabled": true, "minSeverity": "critical"}}'
```

## The config

```json
{
  "dry_run": true,
  "min_severity": "critical",
  "max_actions_per_hour": 10,
  "state_file": "overwing-responder-state.json",
  "pass_env": ["AWS_PROFILE", "AWS_REGION"],
  "allow_private_sources": false,
  "protect": ["arn:aws:iam::\\d{12}:user/break-glass", "ip:(::ffff:)?198\\.51\\.100\\.7"],
  "rules": [
    {
      "name": "quarantine an IAM user",
      "action": "revoke_identity",
      "detectors": ["decoy_touch"],
      "match": "arn:aws:iam::\\d{12}:user/([A-Za-z0-9+=,.@_-]{1,64})",
      "run": ["aws", "iam", "put-user-policy", "--user-name", "{1}", "--policy-name", "overwing-quarantine", "--policy-document", "file://sample/deny-all.json"]
    }
  ]
}
```

A rule says: for this action, when the target matches this expression in full, run this command.
`{target}` is the whole target and `{1}` to `{9}` are the expression's groups. The first rule that
matches wins. The actions Overwing can ask for are `revoke_identity`, `block_source`,
`rotate_secrets` and `quarantine_surface`.

| Field | Default | What it is |
|---|---|---|
| `listen` | `127.0.0.1`, port `8790` | Where the responder listens: `{ "host": ..., "port": ... }`. |
| `overwing_url` | `https://overwing.ai` | Where reports go. |
| `dry_run` | `true` | Nothing is run. Each step is logged and reported as what would have run. |
| `min_severity` | `critical` | `critical`, or `high` to act on high and critical incidents. |
| `max_actions_per_hour` | `10` | How many actions may be taken in an hour. 100 at most. |
| `command_timeout_seconds` | `30` | How long a command may take. 300 at most. |
| `state_file` | `overwing-responder-state.json` | The file the responder keeps its memory in. A relative path is taken from the folder of the config file. `null` keeps the memory in the process only: see the warning below. |
| `pass_env` | `[]` | Names of environment variables a command may see, besides `PATH`, `HOME`, `LANG` and `TZ`. |
| `allow_private_sources` | `false` | Lets `block_source` act on private, loopback and unspecified addresses. |
| `protect` | `[]` | Regular expressions. A target that matches one, in full, is never acted on. |
| `rules` | none; required | The rules: `name`, `action`, `match`, `run`, and optionally `detectors`. With no rule, nothing is ever run. |

A field the responder does not know is an error, so a misspelt one is not silently ignored.
`node src/cli.ts check --config config.json` prints what the config amounts to.

### A rule for some detectors only: `detectors`

Each action in a webhook may say which of Radar's detectors it comes from:

```json
{ "action": "revoke_identity", "surface": null, "actors": ["arn:aws:iam::111122223333:user/svc-reports"], "detectors": ["decoy_touch"], "reason": "..." }
```

A rule with `detectors` matches only an action whose detectors are all in the rule's list. The
rule above quarantines an IAM user when the request comes from a touched decoy (`decoy_touch`).
It does not match a request that comes from `sweep`, nor one that comes from `decoy_touch` and
`sweep` together: to answer both, list both. An action that names no detectors does not match a
rule that has `detectors`. A rule without `detectors` matches whatever the action comes from.
The names are Radar's own, such as `decoy_credential`, `decoy_touch` and `sweep`.

Overwing may name one identity in two actions, each from its own detector. A target is still
acted on once for an incident: by the first rule that answers it, and not again when a later
webhook names it from another detector. So if you give one action two rules, a strict one for
`decoy_touch` and a milder one for the rest, an identity the milder rule has handled is not
handed to the strict rule later in the same incident.

### What a command is given: `pass_env`

A command is run with `PATH`, `HOME`, `LANG` and `TZ` from the responder's environment, when they
are set, and with the variables `pass_env` names. It is given nothing else of that environment,
and never `OVERWING_WEBHOOK_SECRET` or `OVERWING_API_KEY`: a config that lists either is refused.

If a command reads its settings or its credentials from the environment, list those variables:
`AWS_PROFILE` and `AWS_REGION`, for example, or `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
`AWS_SESSION_TOKEN`. Files under your home directory are found as before, because `HOME` is
passed. This is about what a command is handed. A command still runs as the responder's user,
with whatever that user can read.

### Blocking an address: `block_source`, `allow_private_sources`, `protect`

For `block_source`, a target is acted on only when it is `ip:` followed by one IPv4 or IPv6
address. A range (`ip:0.0.0.0/0`), a name (`ip:unknown`) or anything else is skipped, and the
report says why.

The address a decoy key was tried from can be your own: a NAT gateway, a proxy, a load balancer.
Blocking it would cut off your own traffic. So unless `allow_private_sources` is `true`, the
responder does not block an address that is:

- unspecified: `0.0.0.0/8`, `::`
- loopback: `127.0.0.0/8`, `::1`
- private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fec0::/10`
- shared or link-local: `100.64.0.0/10`, `169.254.0.0/16`, `fe80::/10`, and any address with a zone (`fe80::1%eth0`)
- any of the IPv4 ranges above written as IPv6, such as `::ffff:10.0.0.1`

That default cannot know your public addresses. Put your own egress addresses in `protect`: the
addresses your traffic leaves from, such as NAT gateways, proxies, VPN exits and office networks.

`protect` is matched against the target as it is written. The responder does not compare
addresses by value, and one address can be written in more than one way, so write each
expression for the spellings your systems report. In the config above,
`"ip:(::ffff:)?198\\.51\\.100\\.7"` covers `198.51.100.7` as it is and as `::ffff:198.51.100.7`,
the form in which a log often gives an IPv4 address.

### What it remembers: `state_file`

The responder remembers three things: which targets it acted on for which incident (for seven
days), when the actions of the last hour were decided (they count against
`max_actions_per_hour`), and which steps wait for that cap. It keeps them in `state_file`, which
by default is `overwing-responder-state.json` in the folder of the config file.

- The file is written before a webhook is answered and before a command starts. It is written as
  a new file and renamed over the old one, so it is never half written, and only the responder's
  user can read it (mode 0600).
- It holds incidents, targets and times. It never holds a command: what runs is decided from the
  config each time.
- A missing file is an empty memory. A file that cannot be read as the responder's state stops
  `serve` from starting, with a message that names the file: repair it, or move it away to start
  with an empty memory. `serve` also writes the file once as it starts, and does not start if it
  cannot.
- A step that was decided, but whose command had not started when the responder stopped, stays in
  the file as queued and is run after the next start, like any other queued step. A command that
  was running when the responder stopped is not run again: check that one by hand.
- While `dry_run` is on, the file is read and nothing is added to it. What was only rehearsed
  does not count as done, and does not use the hourly cap, once you turn `dry_run` off.
- If the file cannot be written while the responder serves, it logs `state_save_failed` and goes
  on with the memory it has. Fix the cause before the next restart.
- One responder to a state file.

**`"state_file": null` keeps the memory in the process only.** After a restart the responder has
forgotten what it did: a webhook replayed within five minutes of the restart runs again, the
hourly cap starts from zero, and the steps that waited for the cap are lost. Use it only for a
responder that stays in `dry_run`.

### The hourly cap and the queue

At most `max_actions_per_hour` actions are taken in an hour. A step over the cap is not dropped.
It is reported as `skipped`, with a reason that says it is queued, and it waits. The responder
looks at the cap once a minute and runs what waits, oldest first, as room appears. It reports
each of those steps again when it runs it.

- A step that has waited more than 24 hours is not run. It is reported as `skipped`, with that
  reason.
- A queued step is checked again when its turn comes, against the config as it is then:
  `protect`, the rules, `dry_run`.
- At most 1,000 steps wait at one time. Past that, a step is reported as `skipped` and is not
  queued.
- A queued step runs when its turn comes even if the incident was closed in the meantime. To
  cancel what is queued, stop the responder, set `pending` to `[]` in the state file, and start
  it again.

## What keeps it from doing more than it was asked

- A request is refused unless its signature matches your webhook secret, and unless it is less
  than five minutes old. A request of more than 1 MB is refused.
- Nothing runs unless Overwing asked (`response.requested`), the incident is at or above
  `min_severity`, and one of your rules matches the target in full. With no rule, nothing runs. A
  severity the responder does not know counts as the lowest.
- A rule that has `detectors` answers only an action whose detectors are all in its list.
- A command is a list of arguments, run with no shell. A target can fill an argument. It cannot
  choose the program, cannot be an option (a target that starts with `-` is refused), and cannot
  carry a line break.
- What a target fills cannot turn an argument into an option either. If an argument starts with
  `-` once it is filled, and the rule did not write that `-` itself, the step is skipped and the
  report says why. An argument the rule begins with `-`, such as `--reason={target}`, is your own
  option and is allowed. If a value may rightly begin with `-`, write the option and its value as
  one argument, as in `--user-name={1}`.
- A command is given `PATH`, `HOME`, `LANG`, `TZ` and the variables `pass_env` names. It is never
  given the webhook secret or the API key.
- `block_source` acts only on `ip:` followed by one address, and not on a private, loopback or
  unspecified address unless `allow_private_sources` is set.
- A target that matches `protect` is never acted on.
- A target is acted on once for an incident, by the first rule that answers it, however often the
  webhook repeats and whether or not the responder was restarted in between. This is remembered
  for seven days.
- At most `max_actions_per_hour` actions (no config can set it above 100), and a restart does not
  reset the count. A step over the cap waits its turn and is not run after 24 hours. Each command
  has `command_timeout_seconds` to finish.
- The state file never holds a command. A step read from it is run only as your config allows at
  that moment, with the command your own rule names.
- `dry_run` is on until you turn it off: every step is logged and reported as what would have run.
- Reports go to your `overwing_url` and nowhere else, whatever a webhook says.

`npm test` covers each of these.

## What it sends back

One line for each target: the action, the target, `done`, `failed`, `skipped` or `dry_run`, and
the rule's name with the command's exit code, or the reason it was skipped. When a command fails,
the last line it wrote to standard error is added, cut to 300 characters. Nothing else of a
command's output is sent.

A step that waits for the hourly cap is reported twice: as `skipped` when it is queued, and again
when it is run or given up on.

## Changes in 0.2

- A command no longer inherits the responder's environment. List what it needs in `pass_env`.
- The responder keeps a state file beside the config. Its user must be able to write there, or
  `state_file` must point somewhere it can.
- A step over the hourly cap is queued and run later. It used to be dropped.
- `block_source` acts only on `ip:` followed by one address, and by default not on a private one.
- A step is skipped when what the target fills would make an argument start with `-`.
- A rule may be limited to some detectors with `detectors`.
- A webhook may be up to 1 MB. The limit was 256 KB.

## License

MIT.
