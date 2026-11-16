# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssrf-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +short A <allowed-name>; dig +short AAAA <allowed-name>` | Record what the allowlisted name resolves to across A and AAAA before claiming a rebinding or IPv6 gap | Linux, macOS, Windows |
| `curl` | `curl -sS -D - -o /dev/null --max-time 10 'https://target.example/import?url=https://<assessor-controlled-host>/allowlist-baseline'` | Capture the outward baseline headers and status for a controlled destination | Cross-platform |
| `interactsh-client` | `interactsh-client -v` | Observe the originating address of callbacks to prove the server, not the browser, issued the fetch | Cross-platform |

## Minimal Script Shape

A string-versus-resolution checker: for each candidate host it reports whether a suffix allowlist would admit it and whether it actually resolves inward, flagging a bypass when both are true.

```python
import ipaddress
import socket
import sys

ALLOWED_SUFFIX = "feeds.example"

def decision(host):
    allowed_by_string = host.endswith(ALLOWED_SUFFIX)
    inward = False
    for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            inward = True
    return {"host": host, "string_allowed": allowed_by_string,
            "resolves_inward": inward, "bypass": allowed_by_string and inward}

for h in sys.argv[1:]:
    print(decision(h))
```
