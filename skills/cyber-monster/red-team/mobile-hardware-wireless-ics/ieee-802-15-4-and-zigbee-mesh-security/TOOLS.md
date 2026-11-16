# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ieee-802-15-4-and-zigbee-mesh-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `tshark` | `tshark -r join.pcapng -Y zbee_aps` | Join frames and key types from a passive capture | Wireshark CLI |
| `strings` | `strings -a firmware.bin` | Whether the global default key is in the image | POSIX |
| `zigbee2mqtt` | `zigbee2mqtt` with a sniffer coordinator | Network behaviour observation | Node |
| `killerbee` | `zbid`, `zbreplay` | 802.15.4 frame injection and analysis on supported hardware | Python |
| `nRF Sniffer` | 802.15.4 capture in Wireshark | Passive capture where no monitor mode exists | hardware sniffer |

## Minimal script shape

```python
# Classify a Zigbee key model from firmware strings and a join capture.
import re

DEFAULTS = ("zigbeealliance09", "superSecret", "ZigBeeAlliance09")

def key_model(firmware: str, capture_keys: list[str]) -> dict:
    raw = open(firmware, "rb").read()
    text = raw.decode("latin-1", errors="ignore")
    found = [d for d in DEFAULTS if d.lower() in text.lower()]
    return {
        "default_key_in_image": found,
        "link_key_updated": "0x04" in capture_keys,
        "network_key_under_global": "0x01" in capture_keys and "0x04" not in capture_keys,
    }

if __name__ == "__main__":
    print(key_model("firmware.bin", ["0x01"]))
```

`default_key_in_image` non-empty or `network_key_under_global: True` is the finding; `link_key_updated: True` is the control.
