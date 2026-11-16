# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `wpa_supplicant` | `rg -e 'ca_cert' -e 'domain_suffix_match' /etc/wpa_supplicant/` | Whether the client validates the server certificate | wpa_supplicant |
| `hostapd` | `hostapd -B lab-twin.conf` | A lab AP for the acceptance probe | hostapd |
| `tshark` | `tshark -r cap.pcapng -Y "wlan.rsn"` | PMF capability bits in the beacon | Wireshark CLI |
| `hostapd_cli` | `hostapd_cli status` | The AP's own security configuration | hostapd |
| `kismet` | `kismet -c wlan0mon` | Rogue BSSID detection across a site | Kismet |

## Minimal script shape

```python
# Classify an Enterprise client profile by its validation strength.
import re

def classify(profile: str) -> dict:
    has_ca = bool(re.search(r"^\s*ca_cert\s*=", profile, re.M))
    has_suffix = bool(re.search(r"^\s*(domain_suffix_match|domain_match)\s*=", profile, re.M))
    system_store_only = has_ca and "/etc/ssl/certs" in profile
    return {"ca_pinned": has_ca and not system_store_only,
            "domain_bound": has_suffix,
            "finding": not (has_ca and has_suffix) or system_store_only}

if __name__ == "__main__":
    print(classify(open("corp-wifi.conf").read()))
```

`finding: True` is the evil-twin exposure; `ca_pinned` and `domain_bound` both true is the control, and the profile lines are the evidence.
