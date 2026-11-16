# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ics-ot-protocol-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- OPC UA server log: a session established with a deprecated policy or an anonymous token, which the server itself records.
- IDS alert: a Modbus, DNP3, or CIP request from a source outside the zone's approved hosts.
- Zeek log: a new protocol connection pair not present in the baseline.
- Asset inventory: a server whose policy list changed, reviewed on every configuration change.
- Vulnerability intelligence: a product version matching a CISA ICS advisory for the same protocol stack.
- Firewall log: a permit for a controller port from a new source address.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
