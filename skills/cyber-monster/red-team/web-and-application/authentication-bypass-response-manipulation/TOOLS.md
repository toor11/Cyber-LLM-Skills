# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authentication-bypass-response-manipulation`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite` | `Proxy > Options > add match-and-replace '401 Unauthorized' to '200 OK'` | Observe whether the client unlocks on a flipped status while the server data is unchanged | Cross-platform |
| `curl` | `curl -si https://target.example/api/profile` | Inspect the deny-branch body directly for protected fields | Cross-platform |
| `mitmproxy` | `mitmproxy -s flip_flag.py` | Run a response-editing addon that sets the success flag true to confirm client-side trust | Cross-platform |
| `jq` | `jq ".authenticated, .dashboard" <(curl -s https://target.example/login -d @creds)` | Check whether the privileged payload ships regardless of the flag value | Cross-platform |

## Minimal Script Shape

A deny-branch inspector: it requests a protected route with no credential and reports whether the server leaks protected fields in the body of its denial response.

```python
import urllib.error
import urllib.request

ROUTE = "https://target.example/api/profile"
PROTECTED_MARKER = "account_balance"

def fetch(headers):
    req = urllib.request.Request(ROUTE, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")

status, body = fetch({})
leaks = PROTECTED_MARKER in body
print({"status": status, "body_contains_protected_field": leaks,
       "client_side_trust": status in (401, 403) and leaks})
```
