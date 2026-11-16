# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `hcxdumptool` | `hcxdumptool -i wlan0mon -o dump.pcapng` | Captures PMKID and handshake material in a lab | POSIX |
| `hcxpcapngtool` | `hcxpcapngtool -o out.hc22000 cap.pcapng` | Converts a capture into a testable hash format | POSIX |
| `hashcat` | `hashcat -m 22000 out.hc22000 --show` | Whether a candidate set already resolves, which is the entropy evidence | hashcat |
| `aircrack-ng` | `aircrack-ng cap.pcapng` | Handshake presence and quality | aircrack-ng |
| `tshark` | `tshark -r cap.pcapng -Y eapol -T fields -e eapol.type` | Message count, which distinguishes full from partial handshakes | Wireshark CLI |

## Minimal script shape

```python
# Report whether a capture is testable and what entropy the policy implies.
import math
import subprocess

def testable(pcap: str) -> dict:
    out = subprocess.run(["hcxpcapngtool", "-o", "/tmp/x.hc22000", pcap],
                         capture_output=True, text=True).stderr
    return {"handshake": "handshakes" in out.lower(),
            "pmkid": "pmkid" in out.lower(),
            "none": "no hashes" in out.lower()}

def policy_space(chars: int, alphabet: int) -> dict:
    bits = chars * math.log2(alphabet)
    return {"bits": round(bits), "candidates": f"2^{bits:.0f}",
            "days_at_2e6_per_s": f"{2 ** bits / 2e6 / 86400:.3e}"}

if __name__ == "__main__":
    print({"capture": testable("cap.pcapng"), "policy": policy_space(12, 62)})
```

A capture with neither a handshake nor a PMKID cannot support the finding; the `policy` arithmetic is what the report cites for severity.
