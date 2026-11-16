# Detection Signals and Blue-Team Handoff

> Sub-skill: [`tls-and-pki-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- TLS log field: negotiated protocol and cipher suite per connection, alerted on any value below the estate floor.
- Handshake metric: failure rate split by client-offered protocol, which shows who still offers legacy versions.
- Certificate inventory field: `notAfter - notBefore` in days, alerted when a publicly trusted certificate exceeds the applicable SC-081v3 maximum.
- Renewal event: certificates renewed fewer than N days before expiry, which is the manual-process signal.
- CT log signal: a certificate issued for an estate domain by a CA outside the approved list.
- Configuration event: an `ssl_protocols` or `ssl_ciphers` change, or an explicit curve allowlist added.
- Client telemetry: count of connections whose verification was disabled by configuration, which should be zero outside development.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
