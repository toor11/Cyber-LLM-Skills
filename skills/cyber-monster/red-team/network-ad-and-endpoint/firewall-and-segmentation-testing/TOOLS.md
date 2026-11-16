# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`firewall-and-segmentation-testing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap -Pn -p 445,1433,3389 --reason --traceroute 10.20.40.15` | Verdict plus path localisation | Cross-platform |
| `hping3` | `hping3 -S -p 443 -c 3 -I eth0 10.20.40.15` | Bare TCP probe independent of ICMP | Linux |
| `Test-NetConnection` | `Test-NetConnection 10.20.40.15 -Port 1433 -InformationLevel Detailed` | Windows-native path test | Windows |
| `traceroute` | `traceroute -T -p 443 -n 10.20.40.15` | Hop where filtering begins | Linux / macOS |
| `curl` | `curl -sS -x http://proxy:3128 https://internal.example -o /dev/null -w '%{http_code}'` | Proxy-permitted path, a different control | Cross-platform |

## Minimal Lab Validation Script

Run a predicted-verdict matrix and print observed versus expected, so a rule claim can never be made without its prediction.

```python
import socket

CASES = [
    # (src_label, dest, port, expected)
    ("app-tier", "10.20.40.15", 1433, "allow"),
    ("app-tier", "10.20.40.15", 3389, "deny"),
    ("app-tier", "10.20.1.10", 53, "allow"),
]

for label, dest, port, expected in CASES:
    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect((dest, port))
        seen = "allow"
    except OSError:
        seen = "deny"
    finally:
        sock.close()
    print(label, dest, port, "expected", expected, "observed", seen,
          "match" if seen == expected else "MISMATCH")
```

## Flag Notes

- `--reason` turns a state name into evidence; without it a 'filtered' judgement is an opinion.
- `-S <src>` requires raw sockets and only belongs in an authorised boundary test on a controlled link.
- `-T` forces TCP so ICMP filtering does not hide the path.
