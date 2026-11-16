# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authentication-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -s -o /dev/null -w '%{http_code}' https://target.example/api/account` | Capture the unauthenticated status on a protected route as the bypass baseline | Cross-platform |
| `jwt_tool` | `python3 jwt_tool.py <token> -X a` | Check whether the verifier accepts an alg-none or confused token without weaponising it | Cross-platform |
| `ffuf` | `ffuf -w routes.txt -u https://target.example/FUZZ -mc 200 -H 'Cookie: '` | Enumerate routes that return content with no session attached | Cross-platform |
| `Burp Suite Repeater` | `Send the protected request to Repeater, strip the session cookie, and resend` | Confirm the route enforces authentication server-side rather than in the UI | Cross-platform |

## Minimal Script Shape

A gate differential: it requests a protected route anonymously and with an unsigned token, then reports whether the server distinguishes a completed proof from a skipped one.

```python
import urllib.error
import urllib.request

ROUTE = "https://target.example/api/account"

def status(headers):
    req = urllib.request.Request(ROUTE, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code

anonymous = status({})
unsigned = status({"Authorization": "Bearer header.payload."})
print({"anonymous": anonymous, "unsigned_token": unsigned,
       "auth_enforced": anonymous in (401, 403) and unsigned in (401, 403)})
```
