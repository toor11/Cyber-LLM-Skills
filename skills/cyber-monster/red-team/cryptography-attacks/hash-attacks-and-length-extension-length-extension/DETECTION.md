# Detection Signals and Blue-Team Handoff

> Sub-skill: [`hash-attacks-and-length-extension-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Request field: a signed parameter whose decoded length is not a multiple of the block size plus a fixed header, which is where glue padding shows up.
- Application log: MAC verification failures clustered at the first request after a successful one from the same client, which is the shape of an extension attempt.
- Parser signal: a request that produces more fields than the signer's schema allows, rejected or accepted and logged with the field count.
- WAF signal: control bytes (`0x80`) or long zero runs in a signed parameter, which are the mechanical signature of glue padding.
- Code-scanning rule: a raw hash over a concatenation in a function that also calls a parser.
- Error-metric: `ValueError` from a frame or length check on a signing route, which means a probe reached the verifier.
- Cookie audit: a signed cookie whose field count differs from the schema version's expected count.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
