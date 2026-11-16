# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`pivoting-and-tunneling-socks-and-port-forwarding`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ssh` | `ssh -N -L 1433:10.20.40.15:1433 user@foothold` | Local port forward | Cross-platform |
| `ssh` | `ssh -N -D 1080 user@foothold` | Dynamic SOCKS proxy | Cross-platform |
| `proxychains` | `proxychains4 nmap -sT -Pn 10.20.40.15` | TCP connect scan through the proxy | Linux |
| `socat` | `socat TCP-LISTEN:1433,fork TCP:10.20.40.15:1433` | Port relay on the foothold | Linux |
| `ss` | `ss -tn state established` | Established tunnel sockets | Linux |

## Minimal Lab Validation Script

Prove one forwarded port and record the target-side source address, which is the evidence the tunnel carried the traffic.

```python
import socket

def check(host, port, timeout=3, label=""):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        print(label, host, port, "reachable")
    except OSError as exc:
        print(label, host, port, "unreachable", type(exc).__name__)
    finally:
        sock.close()

# localhost listener created by ssh -L, versus the destination directly
check("127.0.0.1", 1433, label="forwarded")
check("10.20.40.15", 1433, label="direct")
```

## Flag Notes

- `-N` opens no shell, which keeps the foothold session minimal.
- `ExitOnForwardFailure=yes` makes ssh exit if the forward cannot bind, which avoids a silently useless tunnel.
- `proxy_dns` in proxychains forces resolution through the tunnel, preventing a DNS leak.
