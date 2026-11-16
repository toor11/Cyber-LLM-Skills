# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`pivoting-and-tunneling-dns-and-icmp-tunnels`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +short NS corp.example` | Delegation records | Cross-platform |
| `tcpdump` | `tcpdump -ni eth0 -w dns.pcap 'udp port 53'` | Query capture for statistics | Linux / macOS |
| `zeek` | `cat dns.log &#124; zeek-cut query qtype_name rcode` | Query inventory | Linux |
| `dnstracer` / `dnstop` | `dnstop -l 3 eth0` | Live query-rate and name-length view | Linux |
| `Get-DnsServerDiagnostics` | `Get-DnsServerDiagnostics` | Query logging state on Windows DNS | Windows |

## Minimal Lab Validation Script

Compute name length and entropy for a query sample, which is the reproducible part of a tunnel finding.

```python
import math
from collections import Counter

def entropy(text):
    counts = Counter(text)
    return -sum((c / len(text)) * math.log2(c / len(text)) for c in counts.values())

QUERIES = [
    "www.corp.example",
    "mail.corp.example",
    "mfrggzdfmztwq2lk.corp.example",
    "nbsuw4z3f5qxs3tjfzzq.corp.example",
]
for name in QUERIES:
    label = name.split(".")[0]
    print(name, "len", len(name), "label_entropy", round(entropy(label), 2))
```

## Flag Notes

- `+short` gives just the record value, which is what a delegation audit needs.
- `-l 3` in dnstop aggregates by top-level domain, which surfaces the parent a tunnel uses.
- Query logging on the resolver is the prerequisite for every statistic in this technique.
