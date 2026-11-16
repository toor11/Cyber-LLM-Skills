# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rsa-attacks-padding-oracle`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Application log: exception class per decrypt route, where a padding-specific class is the inventory entry.
- Response metric: response size and status distribution on the unwrap route split by request hash — a split is the categorical oracle.
- Timing metric: p99/p50 ratio on the unwrap route, tracked continuously rather than measured once.
- Dependency signal: an OpenSSL or language-runtime version below the implicit-rejection fixes on any host that decrypts RSA.
- TLS log: a cipher suite list containing static RSA key exchange, which is the only TLS-reachable instance.
- Access-log pattern: high request volume on the unwrap route from one principal with bodies of equal length, which is the interval-narrowing shape.
- Configuration event: an application-level catch block added to a decrypt handler, caught in review rather than at runtime.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
