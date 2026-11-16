# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prng-and-nonce-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Token-issuance metric: distinct-value ratio and length distribution of issued tokens, which exposes a small or colliding space.
- Application log: a token-issuance route where the generation call is in the same module as a `random` import, flagged by a build-time rule.
- Access-log pattern: sequential or near-sequential token values appearing in requests from one client, which is the prediction shape.
- Authentication metric: success rate on token validation where the submitted token was never issued, which is the guess rate.
- Code-scanning rule: `random` or `Math.random` reachable from a function whose return value is stored as a credential.
- Dependency signal: a library version whose default token generator changed from a PRNG to a CSPRNG.
- Configuration event: removal or replacement of a seed call, which changes the failure mode rather than fixing it.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
