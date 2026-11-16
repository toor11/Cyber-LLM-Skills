# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-recon-and-port-scanning-internal-network-mapping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `arp-scan` | `arp-scan --localnet --interface eth0 --retry 2` | Layer-two neighbour discovery | Linux |
| `nmap` | `nmap -sn -PS22,80,445,3389 --reason 10.20.30.0/24` | Routed discovery with protocol probes | Linux / macOS / Windows |
| `Get-NetNeighbor` | `Get-NetNeighbor -AddressFamily IPv4 &#124; Where-Object State -ne Unreachable` | ARP cache from a Windows foothold | Windows |
| `ip route get` | `ip route get 10.20.40.15` | Next-hop decision for one destination | Linux |
| `netexec` | `netexec smb 10.20.30.0/24 --gen-relay-list relay.txt` | SMB signing state per host, non-destructive | Linux |

## Minimal Lab Validation Script

Produce an edge list where every row names the source that observed it, so the map cannot be read without its vantage point.

```python
import subprocess, xml.etree.ElementTree as ET

SRC = "10.20.30.57"
TARGETS = "10.20.30.0/24"
xml = subprocess.run(["nmap", "-sn", "-PS22,445,3389", "--reason", "-oX", "-", TARGETS],
                     capture_output=True, text=True, check=True).stdout
for host in ET.fromstring(xml).findall("host"):
    if host.find("status").get("state") != "up":
        continue
    addr = host.find("address").get("addr")
    reason = host.find("./ports/extraports").get("reason", "arp-or-echo")
    print(f"{SRC} -> {addr} via {reason}")
```

## Flag Notes

- `-PR` is ARP discovery and only works on the local broadcast domain; using it across a router silently degrades to nothing.
- `--retry 2` keeps a lossy wireless segment from producing phantom missing hosts.
- `-sn` avoids port noise during discovery, which keeps the baseline differential attributable.
