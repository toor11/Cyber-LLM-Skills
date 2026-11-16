# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Device log: a pairing with `AuthReq` lacking MITM, which the peripheral can record and refuse.
- GATT server audit: a write to a control characteristic from a link whose security level is below the required one, which the server enforces and logs.
- Bluetooth IDS: an unexpected central pairing with a known peripheral identity.
- Firmware audit: an SMP configuration that permits Just Works on a device class with actuation.
- Asset inventory: a peripheral whose GATT table changed, reviewed for new writable characteristics.
- Connection metric: a peripheral accepting more than the expected number of bonded centrals.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
