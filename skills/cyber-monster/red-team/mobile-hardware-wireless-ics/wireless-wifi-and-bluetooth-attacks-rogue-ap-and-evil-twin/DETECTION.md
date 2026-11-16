# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Wireless IDS: a BSSID advertising an internal SSID from an unexpected location or radio.
- Association log: a client associating with a BSSID outside the approved list.
- DHCP monitoring: an offer from an address outside the approved scope on a corporate SSID.
- Deauthentication burst: deauth or disassoc frames from a BSSID not in the AP inventory.
- RADIUS log: an authentication request from an AP whose shared secret or source address is not approved.
- Client log: an EAP failure caused by certificate validation, which is the control firing.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
