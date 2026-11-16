# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-request-smuggling-client-side-desync`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Enable HTTP/1.1, uncheck 'Update Content-Length', and use 'Send group in sequence (single connection)'` | Reproduce the prime-then-follow-up sequence on one connection to confirm the stranded prefix | Cross-platform |
| `Chrome DevTools` | `Network panel with 'Connection ID' column enabled to confirm socket reuse between requests` | Verify the browser actually pools and reuses the connection the desync depends on | Cross-platform |
| `curl` | `curl -sS -i --http1.1 -X GET --data 'x' https://target.example/static/health` | Check whether a GET with a body is accepted and the connection kept alive, the CSD carrier precondition | Cross-platform |
| `Playwright` | `npx playwright codegen https://attacker-page.example` | Drive a real browser through the attacker page so connection pooling is exercised as a victim's browser would | Cross-platform |

## Minimal Script Shape

A client-side-desync carrier probe: over a single HTTP/1.1 connection it sends a GET that carries a small body and checks whether the server answers 200 and keeps the connection open, which is the precondition for stranding bytes, then reports the verdict.

```python
import http.client
import ssl

HOST = "target.example"
PATH = "/static/health"

def probe():
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=10)
    conn.putrequest("GET", PATH, skip_accept_encoding=True)
    body = b"x"
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    resp = conn.getresponse()
    keep_alive = resp.getheader("Connection", "").lower() != "close"
    status = resp.status
    conn.close()
    return status, keep_alive

status, keep_alive = probe()
print({"status": status, "keep_alive": keep_alive,
       "csd_carrier": status == 200 and keep_alive})
```
