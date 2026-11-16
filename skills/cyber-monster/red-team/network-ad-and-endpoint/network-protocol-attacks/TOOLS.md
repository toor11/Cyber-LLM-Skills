# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-protocol-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `arping` | `arping -I eth0 -c 3 -D 10.20.30.1` | Duplicate-address detection, non-destructive | Linux |
| `tcpdump` | `tcpdump -ni eth0 'arp or (udp port 5355) or (udp port 137)'` | Witness the exchange on the wire | Linux / macOS |
| `Responder` | `Responder.py -I eth0 -A` | Analysis mode only: log responders without answering | Linux |
| `mitm6` | `mitm6 -d corp.example --no-ra --ignore-nofqdn` | Scope DHCPv6 DNS assignment behaviour in a lab | Linux |
| `Get-DnsClientCache` | `Get-DnsClientCache &#124; Sort-Object -Property Entry` | Victim-side resolver state | Windows |

## Minimal Lab Validation Script

Record the victim's neighbour and resolver state before and after a controlled probe; the script never answers on behalf of a service.

```python
import subprocess, json

def snapshot(host):
    arp = subprocess.run(["ip", "-j", "neigh"], capture_output=True, text=True).stdout
    return {e["dst"]: e.get("lladdr") for e in json.loads(arp)}

before = snapshot("10.20.30.0/24")
input("run the single controlled probe now, then press enter")
after = snapshot("10.20.30.0/24")
for addr in sorted(set(before) | set(after)):
    if before.get(addr) != after.get(addr):
        print("changed", addr, before.get(addr), "->", after.get(addr))
```

## Flag Notes

- `-A` on Responder is analysis mode: it logs without answering, which is the only non-destructive setting.
- `-D` on arping performs duplicate-address detection without claiming the address.
- `--no-ra` keeps mitm6 from advertising a router, limiting the change to DNS assignment in a lab.
