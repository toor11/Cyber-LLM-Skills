# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-protocol-attacks-name-resolution-poisoning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Responder` | `Responder.py -I eth0 -A -v` | Analysis mode: log queries and responders without answering | Linux |
| `tcpdump` | `tcpdump -ni eth0 -w llmnr.pcap 'udp port 5355 or udp port 137 or udp port 5353'` | Capture the broadcast name traffic | Linux / macOS |
| `ntlmrelayx.py` | `ntlmrelayx.py -tf targets.txt -smb2support -socks` | Relay path for a captured authentication, with signing preconditions | Linux |
| `Resolve-DnsName` | `Resolve-DnsName name -LlmnrNetbiosOnly -QuickTimeout` | Victim-side resolution result | Windows |
| `Get-SmbConnection` | `Get-SmbConnection &#124; Select-Object ServerName,Dialect,Encrypted` | What the client believes it connected to | Windows |

## Minimal Lab Validation Script

Log responders and queries only; the script never answers, so it can run on a production segment without capturing credentials.

```python
from scapy.all import sniff, UDP, IP, DNSQR

def note(pkt):
    if pkt.haslayer(DNSQR) and pkt[UDP].dport in (5355, 5353):
        print(pkt[IP].src, pkt[UDP].dport, pkt[DNSQR].qname.decode(errors="replace"))

sniff(iface="eth0", prn=note, store=False, timeout=60,
      filter="udp and (port 5355 or port 5353 or port 137)")
```

## Flag Notes

- `-A` puts Responder in analysis mode, which answers nothing and only logs.
- `-smb2support` is required for relay against modern SMB, but relaying needs its own written authorisation.
- `-QuickTimeout` keeps a victim-side probe from waiting on a name that will never resolve.
