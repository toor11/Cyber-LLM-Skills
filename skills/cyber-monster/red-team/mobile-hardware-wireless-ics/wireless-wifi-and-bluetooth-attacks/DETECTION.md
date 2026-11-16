# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Wireless IDS: a deauthentication or disassociation burst, which indicates a management-frame attack or a rogue AP.
- Association log: a client associating with PSK on a network configured for SAE, which is the downgrade signal.
- RADIUS log: an authentication from an AP whose certificate does not match the expected one.
- Bluetooth event: a pairing with Just Works on a device that should require a passkey.
- Monitor-mode capture: a beacon with an AKM set that differs from the approved configuration.
- Asset inventory: a rogue BSSID advertising an internal SSID, which is the evil-twin signal.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
