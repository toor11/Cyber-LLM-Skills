# Detection Signals and Blue-Team Handoff

> Sub-skill: [`constant-time-and-crypto-side-channel-code-audit`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Response-time metric: p99 minus p50 on a verification route, tracked as a ratio so traffic growth does not mask a shift.
- Access-log pattern: request latency clustered by the matching-prefix length of the submitted token, which is only visible if the tag is logged (do not log it).
- Code-scanning rule: an equality operator whose left operand name matches `mac|tag|digest|signature|token` and whose right operand is not a constant-time primitive.
- Build event: a compiler optimisation-level or target change on a crate containing crypto code, which is when constant-time source becomes non-constant-time binary.
- Dependency advisory: a library version named in a published timing finding for the same primitive family.
- Error-rate metric: authentication failures per source address in a narrow time window, which is the observable shape of a byte-at-a-time timing campaign.
- Instrumentation signal: a `memcmp` or `strcmp` calling into a comparison against a buffer that also appears in key-derivation frames.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
