# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`c2-infrastructure-and-redirectors`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `openssl` | `openssl s_client -connect host:443 -servername host` | Certificate subject, issuer and validity | Cross-platform |
| `curl` | `curl -sSI https://host/` | Response headers and redirect chain | Cross-platform |
| `dig` | `dig +short A suspect.example` | Resolution and TTL | Cross-platform |
| `zeek` | `cat ssl.log &#124; zeek-cut server_name issuer subject` | TLS metadata across a capture window | Linux |
| `tcpdump` | `tcpdump -ni eth0 -w dns.pcap 'udp port 53'` | DNS query capture for a window | Linux / macOS |

## Minimal Lab Validation Script

Report the endpoint's certificate and header profile plus the estate's visibility gap, which is the actionable part.

```python
import socket, ssl

def profile(host, port=443, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as tls:
            cert = tls.getpeercert()
            print(host, "issuer", cert.get("issuer"), "subject", cert.get("subject"),
                  "notBefore", cert.get("notBefore"))

for host in ("suspect.example",):
    try:
        profile(host)
    except Exception as exc:
        print(host, "no-tls", type(exc).__name__)
```

## Flag Notes

- `-servername` sends SNI, which is required to see the certificate a shared host would present.
- `-sSI` fetches headers without a body, the least intrusive way to profile a redirector.
- `zeek-cut` extracts named fields from the TLS log, which makes certificate profiling a single command.
