# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authorization-and-idor-function-level`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp AuthMatrix` | `Define roles and endpoints, then run the matrix` | Map which privileged actions each role can reach in one pass | Cross-platform |
| `curl` | `curl -si -X DELETE https://target.example/api/admin/users/42 -H 'Cookie: session=low'` | Test a privileged verb as a low-privilege user and read the status | Cross-platform |
| `ffuf` | `ffuf -w admin-routes.txt -u https://target.example/FUZZ -H 'Cookie: session=low' -mc 200,201,204` | Find admin functions reachable under a low-privilege session | Cross-platform |

## Minimal Script Shape

A verb matrix: it calls an admin function across methods with a low-privilege session and reports which verbs the endpoint fails to gate.

```python
import urllib.error
import urllib.request

ROUTE = "https://target.example/api/admin/users"

def call(method, cookie):
    req = urllib.request.Request(ROUTE, method=method, headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code

low = "session=<low-priv>"
rows = {method: call(method, low) for method in ("GET", "POST", "PUT", "DELETE")}
reachable = [method for method, code in rows.items() if code in (200, 201, 204)]
print({"verbs": rows, "bfla_reachable_verbs": reachable})
```
