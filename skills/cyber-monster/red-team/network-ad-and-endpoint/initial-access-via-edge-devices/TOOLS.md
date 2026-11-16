# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`initial-access-via-edge-devices`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sSI https://vpn.example.com/` | Headers and redirect behaviour of the login surface | Cross-platform |
| `nmap` | `nmap -Pn -p 443,8443,10443 --script ssl-cert vpn.example.com` | Service and certificate identity | Cross-platform |
| `openssl` | `openssl s_client -connect host:443 -servername host` | TLS stack and certificate validity | Cross-platform |
| Vendor advisory portal | Search by exact build number | Fix version and exploitation status | Cross-platform |
| `show` commands on the appliance | `show running-config`, `show syslog`, `show admin` | Configuration and log destination state | Network device |

## Minimal Lab Validation Script

Record the appliance's exposed plane, build string and logging state; no exploitation is attempted by this probe.

```python
import socket, ssl

def surface(host, port=443, timeout=6):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                cert = tls.getpeercert()
                print(host, port, "issuer", cert.get("issuer"), "notAfter", cert.get("notAfter"))
    except Exception as exc:
        print(host, port, "no-tls", type(exc).__name__)

for port in (443, 8443, 10443):
    surface("vpn.example.com", port)
```

## Flag Notes

- `-Pn` skips discovery so a filtered ICMP path does not hide the appliance.
- `--reason` gives the state name, which is what a perimeter finding must cite.
- `-servername` is required for SNI, without which many appliances return a default certificate.
