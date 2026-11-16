# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`rest-and-grpc-api-security`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `grpcurl` | `grpcurl -plaintext target.example:50051 list` | Enumerate services and methods via server reflection to test per-method authorization | Cross-platform |
| `schemathesis` | `schemathesis run https://target.example/openapi.json --checks all` | Drive schema-derived cases including authorization and response-shape checks | Cross-platform |
| `Burp Autorize` | `Configure a second account's cookies and replay each request automatically` | Flags object- and function-level authorization gaps across the sitemap | Cross-platform |

## Minimal Script Shape

A BOLA differential harness: it requests one object id with two account tokens and reports whether the second account receives the first account's object, which confirms missing object-level authorization.

```python
import urllib.error
import urllib.request

BASE = "https://target.example/api/orders/"
OBJECT_ID = "1002"           # owned by account A
TOKEN_A = "Bearer token-a"
TOKEN_B = "Bearer token-b"

def fetch(object_id, token):
    req = urllib.request.Request(BASE + object_id, headers={"Authorization": token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""

status_a, body_a = fetch(OBJECT_ID, TOKEN_A)
status_b, body_b = fetch(OBJECT_ID, TOKEN_B)
cross_account = status_b == 200 and body_b == body_a and body_a != b""
print({"owner_status": status_a, "other_status": status_b,
       "bola_confirmed": cross_account})
```
