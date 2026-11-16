# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ics-ot-protocol-attacks-ot-network-architecture`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Firewall log: a permit to a controller port from a source outside the conduit's host list.
- Flow data: a new host-to-controller pair that has no change record.
- Route audit: a host appearing with interfaces in two zones, which the CMDB should not allow.
- VPN log: a session whose assigned address is inside a control subnet.
- Wireless controller log: a bridge association carrying a control protocol.
- Vendor appliance log: a tunnel session outside its scheduled window.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
