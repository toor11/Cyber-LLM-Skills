# Verification Probes and Expected Differentials

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Pairing-method observation

```text
# The pairing method appears in the SMP exchange, in the clear.
sudo btmon -w /tmp/pair.log &
bluetoothctl --timeout 30 pair AA:BB:CC:DD:EE:FF
grep -a -A3 "SMP Pairing" /tmp/pair.log | head -20
```

Expected differential: `AuthReq` with MITM and Secure Connections set plus Passkey Entry or Numeric Comparison is the control; `AuthReq: 0x00` with Just Works is the finding.

## Class 2 — GATT table and permissions

```text
# Every characteristic with its properties and security requirements.
gatttool -b AA:BB:CC:DD:EE:FF --characteristics
python - <<'WIRELESSWIFIANF93D_CLASS2'
from bleak import BleakClient
async def main():
    async with BleakClient("AA:BB:CC:DD:EE:FF") as c:
        for s in c.services:
            for ch in s.characteristics:
                print(s.uuid, ch.uuid, ch.properties)
import asyncio; asyncio.run(main())
WIRELESSWIFIANF93D_CLASS2
```

Expected differential: a control characteristic with `write` and no encryption requirement is the finding; `write` combined with an authenticated-link requirement is the control.

## Class 3 — Write probe (lab device only)

```text
# Does an unpaired or Just Works central get to write?
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0012 -n 01
```

Expected differential: an `Authentication Requirements` or `Insufficient Encryption` error is the control; `Characteristic value was written successfully` is the finding, and the characteristic UUID is the evidence.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
