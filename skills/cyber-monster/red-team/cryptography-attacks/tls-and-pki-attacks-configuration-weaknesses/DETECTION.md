# Detection Signals and Blue-Team Handoff

> Sub-skill: [`tls-and-pki-attacks-configuration-weaknesses`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- TLS log field: negotiated protocol and suite per connection, alerted on any value below the floor.
- Handshake metric: success rate per offered protocol version, which shows whether legacy clients still complete.
- Configuration event: an `ssl_protocols`, `ssl_ciphers`, or curve-allowlist change in a deploy diff.
- Scanner result: an estate sweep delta where a previously compliant endpoint gained a legacy protocol.
- Session metric: ticket key age, where a static key shows as a constant age across restarts.
- Error pattern: protocol alerts (`protocol_version`, `handshake_failure`) spiking, which indicates a client population that cannot meet the floor.
- Compression signal: a negotiated `Compression` other than `NONE` in any handshake log.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
