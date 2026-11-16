# Detection Signals and Blue-Team Handoff

> Sub-skill: [`post-quantum-cryptography-migration-and-hybrids`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- TLS log field: negotiated group per connection, rolled up per endpoint, which is the migration-progress metric.
- Protocol alert: a HelloRetryRequest rate spike after a group-order change, which means a middlebox or allowlist is fighting the new default.
- Inventory field: signature algorithm OID per certificate, alerted when a new certificate is issued with a quantum-vulnerable signature after the estate's cutover date.
- Configuration event: an explicit curve allowlist added to a terminator, which silently reverts a library default.
- Dependency signal: a TLS library version gaining or losing the hybrid group name, which changes behaviour with no config change.
- Key-management event: a KMS key created with an RSA or EC key spec in a service that has a migration deadline.
- Client telemetry: fraction of connections negotiating a hybrid group by client family, which shows whether the long tail is clients or servers.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
