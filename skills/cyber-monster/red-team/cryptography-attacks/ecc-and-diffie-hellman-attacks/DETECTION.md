# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ecc-and-diffie-hellman-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- TLS log field: handshake failures with an `illegal_parameter` alert, which is what a conforming stack returns for a bad point.
- Application log: `exchange(` or `compute_key` call sites reached with a peer key whose curve name differs from the configured one.
- Cryptographic metric: distribution of derived shared-secret values, hashed and counted, per peer identity — a repeated value across sessions is the low-order signature.
- Signature audit: duplicate `r` values across distinct message hashes in one key's signature history.
- Configuration event: a curve identifier change in a TLS or key-exchange config, especially toward a legacy short curve.
- Dependency advisory: a library version named in a validation-bypass advisory for the same ECDH entry point.
- Build signal: a target architecture change on a crate containing scalar multiplication, which is when constant-time assumptions need re-verification.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
