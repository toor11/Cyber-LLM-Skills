# Detection Signals and Blue-Team Handoff

> Sub-skill: [`signature-and-mac-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Authentication log: a request whose signature verified while a header or query field differed from the signed body's corresponding field.
- Token header field: an `alg` value that differs from the key's configured algorithm, which is the confusion attempt.
- Replay-cache metric: two authorisations with the same logical content but different signature encodings, which is the malleability signal.
- Request field: signature verification on a callback whose tenant, amount, or account arrives outside the signed body.
- Code-scanning rule: a JWT verification call whose algorithm list is derived from the token.
- Error pattern: verification failures that mention an algorithm name the key does not use.
- Audit record: one signature presented to two different endpoints, which is the cross-context reuse shape.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
