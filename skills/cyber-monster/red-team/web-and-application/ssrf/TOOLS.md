# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssrf`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null --max-time 10 'https://target.example/api/preview?url=https://example.org/'` | Capture the headers and status the preview endpoint returns for a benign destination, which is the differential baseline | Cross-platform |
| `dig` | `dig +short A <allowed-host> @1.1.1.1` | Confirm what the allowlisted hostname currently resolves to before claiming a rebinding gap | Linux, macOS, Windows |
| `interactsh-client` | `interactsh-client -v` | Collect DNS and HTTP callbacks with the originating address so server-versus-browser origin is provable | Cross-platform |
| `Burp Collaborator` | `Generate Collaborator payload, insert as the `url` value, then poll the Collaborator tab` | Same oracle inside an intercepting proxy so the paired baseline stays on one connection | Cross-platform |

## Minimal Script Shape

A resolver-versus-validator checker: it asks what a hostname resolves to and flags any answer that is not publicly routable, so a suspected bypass can be verified without issuing the fetch.

```python
import ipaddress
import socket
import sys


def classify(host, port=443):
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    rows = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        rows.append({
            "address": str(addr),
            "private": addr.is_private,
            "loopback": addr.is_loopback,
            "link_local": addr.is_link_local,
            "reserved": addr.is_reserved,
        })
    return rows


for host in sys.argv[1:]:
    for row in classify(host):
        bad = row["private"] or row["loopback"] or row["link_local"] or row["reserved"]
        print(host, row, "INWARD" if bad else "public")
```
