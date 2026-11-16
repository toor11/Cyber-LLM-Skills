# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Wireless IDS: a PMKID request, which is a distinctive management frame pattern.
- AP log: an association and immediate disassociation burst, which is the forced-rehandshake shape.
- Monitor capture: a beacon whose AKM set differs from the approved configuration.
- Authentication log: a single client producing many handshakes in a short window.
- Network policy audit: a PSK network with a passphrase shorter than the documented policy.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
