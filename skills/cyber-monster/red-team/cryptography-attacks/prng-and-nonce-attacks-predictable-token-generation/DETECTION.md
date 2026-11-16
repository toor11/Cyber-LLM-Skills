# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prng-and-nonce-attacks-predictable-token-generation`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Access-log field: failed redemption attempts per token and per account, alerted above a small threshold.
- Schema field: presence of `used_at`, `expires_at`, and `user_id` on the token table, checked on every migration.
- Metric: distinct tokens issued per minute versus distinct tokens redeemed, where the ratio indicates enumeration.
- Request field: token values in query strings reaching proxy or CDN logs, which is the exposure signal.
- Application log: a redemption that succeeds for a user id different from the issuing user id.
- Session signal: one token redeemed from two source addresses, which is the transfer or replay shape.
- Code-scanning rule: a reset or invitation flow whose generation call is not a CSPRNG or whose comparison has no attempt counter.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
