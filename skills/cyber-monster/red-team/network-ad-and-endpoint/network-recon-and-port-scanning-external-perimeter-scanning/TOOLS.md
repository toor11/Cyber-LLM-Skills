# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-recon-and-port-scanning-external-perimeter-scanning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap -sS -Pn -p- --reason --open -oA ext-full 198.51.100.0/24` | External full-range sweep with reasons | Linux / macOS |
| `curl` | `curl -sS -D - -o /dev/null --resolve portal.example.com:443:198.51.100.20 https://portal.example.com` | Layer identification with name pinned to IP | Cross-platform |
| `openssl s_client` | `openssl s_client -connect 198.51.100.20:443 -servername portal.example.com -showcerts` | Certificate and TLS stack inspection | Cross-platform |
| `whois` / RIR lookup | `whois -h whois.arin.net 198.51.100.20` | Ownership check before scanning | Linux / macOS |
| `crt.sh` query | `curl -sS 'https://crt.sh/?q=%25.example.com&output=json'` | Published hostname discovery | Cross-platform |

## Minimal Lab Validation Script

Classify each responding port by which layer answered, so a CDN edge is never reported as an exposed origin.

```python
import socket, ssl

def classify(ip, port, sni=None, timeout=5):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=sni) as tls:
                cert = tls.getpeercert()
                print(ip, port, "tls", cert.get("issuer"), tls.version())
    except (socket.timeout, ConnectionError, ssl.SSLError) as exc:
        print(ip, port, "no-exchange", type(exc).__name__)

classify("198.51.100.20", 443, "portal.example.com")
```

## Flag Notes

- `--open` keeps the report to reachable services, but keep the unfiltered output too or you lose the negative evidence.
- `--resolve` pins a hostname to an IP so the TLS layer answers for the origin instead of DNS.
- `--reason` is mandatory for any perimeter claim; state names are the audit trail.
