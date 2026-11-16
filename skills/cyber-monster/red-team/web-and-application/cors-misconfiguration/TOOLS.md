# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cors-misconfiguration`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/api/me' -H 'Origin: https://cors-probe.assessor.test'` | Show the allow-origin and allow-credentials headers returned for an attacker Origin | Cross-platform |
| `CORScanner` | `python cors_scan.py -u https://target.example/api/me` | Enumerate reflected-origin, null, and wildcard-with-credentials conditions on a target URL | Cross-platform |
| `Burp Suite Repeater` | `Set the Origin header, then compare the two Access-Control-* response headers` | Keep the benign and attacker Origin requests side by side for the header differential | Cross-platform |

## Minimal Script Shape

A CORS header differential: it sends an attacker Origin and reports whether the response reflects it into Access-Control-Allow-Origin together with credentials true.

```python
import urllib.request

ENDPOINT = "https://target.example/api/me"

def acao_for(origin):
    req = urllib.request.Request(ENDPOINT, headers={"Origin": origin})
    with urllib.request.urlopen(req, timeout=10) as r:
        return (r.headers.get("Access-Control-Allow-Origin"),
                r.headers.get("Access-Control-Allow-Credentials"))

attacker = "https://cors-probe.assessor.test"
allow_origin, allow_creds = acao_for(attacker)
# Reflecting the attacker origin with credentials true is the finding
reflected = allow_origin == attacker and (allow_creds or "").lower() == "true"
print({"allow_origin": allow_origin, "allow_credentials": allow_creds,
       "origin_reflected_with_creds": reflected})
```
