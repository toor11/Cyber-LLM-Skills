# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `btmon` | `sudo btmon -w /tmp/pair.log` | The pairing exchange including the method and `AuthReq` | BlueZ |
| `bluetoothctl` | `bluetoothctl --timeout 30 pair MAC` | Pairing with method reporting | BlueZ |
| `gatttool` | `gatttool -b MAC --characteristics` | The GATT table with properties | BlueZ |
| `bleak` | `python -c "import asyncio, bleak; ..."` | Cross-platform GATT enumeration with properties | Python |
| `nRF Connect` | app-based GATT browser | A GUI view of services and permissions for a quick pass | mobile app |

## Minimal script shape

```python
# Classify a pairing log and a GATT dump into finding or control.
import re

def pairing(log: str) -> dict:
    auth = re.search(r"AuthReq: 0x([0-9a-f]{2})", log)
    method = re.search(r"Pairing method: ([A-Za-z ]+)", log)
    flags = int(auth.group(1), 16) if auth else 0
    return {"method": method.group(1).strip() if method else "unknown",
            "mitm": bool(flags & 0x04),
            "secure_connections": bool(flags & 0x08),
            "just_works": "Just Works" in log}

def gatt(rows: list[dict]) -> list[dict]:
    return [r for r in rows if "write" in r["properties"].lower()
            and not r.get("authenticated", False)]

if __name__ == "__main__":
    print({"pairing": pairing(open("/tmp/pair.log", errors="ignore").read())})
```

`just_works: True` on a device with an actuator is the finding; a writable characteristic with no authentication flag is the second, and both are needed for the full picture.
