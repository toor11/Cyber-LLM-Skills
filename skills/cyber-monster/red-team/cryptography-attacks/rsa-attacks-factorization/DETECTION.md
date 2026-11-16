# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rsa-attacks-factorization`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Certificate inventory event: a new modulus whose GCD against the existing estate is non-trivial, checked on every issuance.
- Key-generation telemetry: the modular gap between `p` and `q` recorded at generation, alerted when it falls below a threshold.
- Build signal: a key-generation path in a build script or firmware image, which is where weak generators survive.
- Cryptographic metric: per-key time-to-generate distribution, where an unusually fast generation indicates a local prime search.
- Dependency advisory: an RNG or key-generation library version named in a shared-prime advisory.
- Audit record: the same RNG seed or entropy source used for two key-generation events on different hosts.
- Firmware field: modulus bit length below the organisational floor in an image inventory.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
