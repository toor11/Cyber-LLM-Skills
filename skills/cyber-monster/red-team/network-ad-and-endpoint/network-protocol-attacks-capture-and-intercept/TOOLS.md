# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-protocol-attacks-capture-and-intercept`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tcpdump` | `tcpdump -ni eth0 -w cap.pcap 'host 10.20.30.50 and tcp port 445'` | Bounded capture of one flow | Linux / macOS |
| `arpspoof` | `arpspoof -i eth0 -t 10.20.30.50 10.20.30.1` | Two-host ARP redirect for a bounded window | Linux |
| `bettercap` | `bettercap -iface eth0 -eval 'set arp.spoof.targets 10.20.30.50; arp.spoof on'` | Scripted two-host redirect with restore | Linux |
| `Get-NetNeighbor` | `Get-NetNeighbor -AddressFamily IPv4 -State Reachable` | Victim-side neighbour table | Windows |
| `dumpcap` | `dumpcap -i 3 -f 'host 10.20.30.50' -a duration:60 -w victim.pcapng` | Time-bounded capture on Windows | Windows |

## Minimal Lab Validation Script

Correlate the victim's neighbour table with the capture, so an interception claim always carries both halves of the evidence.

```python
import json, subprocess, time

VICTIM, GW = "10.20.30.50", "10.20.30.1"

def entries():
    raw = subprocess.run(["ip", "-j", "neigh", "show", "dev", "eth0"],
                         capture_output=True, text=True).stdout
    return {e["dst"]: e.get("lladdr") for e in json.loads(raw)}

prev = entries()
print("baseline", prev.get(GW))
time.sleep(30)   # window in which the authorised redirect runs
now = entries()
print("after", now.get(GW), "changed" if now.get(GW) != prev.get(GW) else "unchanged")
```

## Flag Notes

- `-w` writes pcap for later protocol analysis; `-c` bounds the capture so nothing runs unbounded.
- `-t victim gateway` limits arpspoof to one target; omitting `-t` poisons the whole segment.
- `-a duration:60` gives dumpcap a hard stop, which keeps a Windows capture from being left running.
