# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rsa-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- TLS log field: cipher suites with `RSA` key exchange (not `ECDHE_RSA`), which is the only place Bleichenbacher decryption padding is reachable in TLS.
- Application log: exception class per decrypt route, where a padding-specific class is the oracle inventory.
- Certificate inventory field: modulus bit length and exponent per leaf and intermediate, reviewed on issuance.
- Cryptographic metric: GCD collisions across the estate's moduli, run on every key-inventory refresh.
- Signature-verification metric: acceptance rate for signatures whose encoded length differs from the modulus length.
- Dependency advisory: an OpenSSL or language-runtime version named in a padding-oracle or timing advisory.
- Configuration event: a cipher-suite list change that reintroduces static RSA key exchange.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
