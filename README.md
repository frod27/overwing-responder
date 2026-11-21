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
- `OVERWING_API_KEY`: used only to report back what was done. A key of scope `swarm` is enough.
  Without it the responder acts and logs, and reports nothing.
- `OVERWING_RESPONDER_NAME`: a name for this responder in the reports.

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
  "protect": ["arn:aws:iam::\\d{12}:user/break-glass"],
  "rules": [
    {
      "name": "quarantine an IAM user",
      "action": "revoke_identity",
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

## What keeps it from doing more than it was asked

- A request is refused unless its signature matches your webhook secret, and unless it is less
  than five minutes old.
- Nothing runs unless Overwing asked (`response.requested`), the incident is at or above
  `min_severity`, and one of your rules matches the target in full. With no rule, nothing runs.
- A command is a list of arguments, run with no shell. A target can fill an argument. It cannot
  choose the program, cannot be an option (a target that starts with `-` is refused), and cannot
  carry a line break.
- A target that matches `protect` is never acted on.
- A target is acted on once for an incident, however often the webhook repeats.
- At most `max_actions_per_hour` actions (no config can set it above 100), and each command has
  `command_timeout_seconds` to finish.
- `dry_run` is on until you turn it off: every step is logged and reported as what would have run.
- Reports go to your `overwing_url` and nowhere else, whatever a webhook says.

`npm test` covers each of these.

## What it sends back

One line for each target: the action, the target, `done`, `failed`, `skipped` or `dry_run`, and
the rule's name with the command's exit code. Never the command's output.

## License

MIT.
