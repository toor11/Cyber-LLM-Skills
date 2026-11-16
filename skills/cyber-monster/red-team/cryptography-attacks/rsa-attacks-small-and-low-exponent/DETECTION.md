# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rsa-attacks-small-and-low-exponent`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Certificate or JWKS field: `e` equal to 3 on any key that encrypts, reviewed at issuance.
- Protocol field: a ciphertext whose length equals the modulus length and whose repeated use across recipients is visible in a wrapping service log.
- Application log: an encrypt call with an explicit `NoPadding` or a raw modexp warning.
- Cryptographic metric: distribution of plaintext sizes on the RSA encrypt path relative to the modulus, where a cluster well below `n^(1/3)` is the exposure.
- Code-scanning rule: `pow(` or `modPow(` called directly on message bytes in an encryption path.
- Dependency event: a library default changing from `e=3` to `e=65537`, which changes the branch set for new keys.
- Audit record: the same plaintext hash encrypted to multiple recipients in one request, which is the Hastad shape.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
