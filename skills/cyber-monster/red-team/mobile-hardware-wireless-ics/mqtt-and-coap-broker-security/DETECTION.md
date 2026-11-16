# Detection Signals and Blue-Team Handoff

> Sub-skill: [`mqtt-and-coap-broker-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Broker log: a CONNECT without a username, which is the anonymous-access signal.
- Broker log: a subscription to `#` from a device client, which is the enumeration shape.
- ACL denial counter: a publish rejected outside a client's prefix, which is the control firing.
- Topic metric: retained-message count per topic pattern, which exposes wildcard retained state at scale.
- Bridge log: message counts per filter, where a bridge with `#` shows every topic class.
- Network flow: a CoAP request to `/.well-known/core` from an unexpected source.
- Device audit: a client certificate identity that does not match its topic prefix.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
