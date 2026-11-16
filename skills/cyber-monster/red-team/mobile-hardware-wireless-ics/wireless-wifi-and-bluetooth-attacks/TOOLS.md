# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `tshark` | `tshark -r cap.pcapng -Y "wlan.fc.type_subtype == 8"` | Beacon parameters including AKM and MFP | Wireshark CLI |
| `aircrack-ng` | `aircrack-ng cap.pcapng` | Whether a captured handshake contains crackable material, in a lab | aircrack-ng |
| `wpa_cli` | `wpa_cli status` | The client's negotiated key management | wpa_supplicant |
| `bluetoothctl` | `bluetoothctl --timeout 20 scan on` then `info MAC` | Pairing mode and paired state | BlueZ |
| `btmon` | `btmon -w capture.btsnoop` | Pairing exchange details including the method | BlueZ |

## Minimal script shape

```python
# Classify Wi-Fi configuration strength from a beacon parameter dump.
def classify(akms: set[str], mfpr: bool, transition: bool) -> str:
    if "SAE" in akms and akms == {"SAE"} and mfpr and not transition:
        return "control: SAE-only, PMF required, transition disabled"
    if "PSK" in akms and "SAE" in akms:
        return "finding: transition mode, PSK handshake available"
    if "PSK" in akms:
        return "finding: shared-passphrase model"
    if "802.1X" in akms and not mfpr:
        return "finding: enterprise without PMF; check client certificate validation"
    return "review: unusual AKM set"

if __name__ == "__main__":
    print(classify({"PSK", "SAE"}, mfpr=False, transition=True))
```

The returned string is the classification; each `finding:` names the specific weakness so the report does not have to re-derive it.
