# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`oauth-oidc-misconfiguration`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i 'https://idp.example/authorize?response_type=code&client_id=app&redirect_uri=https://app.example/oauth/callback&state=abc'` | Capture the clean authorization response as the baseline before tampering a parameter | Cross-platform |
| `Burp Suite` | `Intercept the authorize request and the token exchange, then edit one parameter per repeat in Repeater` | Isolate a single tampered parameter against the baseline flow | Cross-platform |
| `jwt_tool` | `python jwt_tool.py <id_token>` | Inspect id_token claims (iss, aud, nonce, scope) to see which validations the client must enforce | Cross-platform |
| `curl (OIDC discovery)` | `curl -sS 'https://idp.example/.well-known/openid-configuration'` | Enumerate endpoints and supported methods (PKCE, response types) to scope the applicable checks | Cross-platform |

## Minimal Script Shape

A redirect-matching harness: it issues a baseline authorize with the registered redirect and a tampered authorize with a traversal suffix, then flags loose matching if the tampered request still produces a redirect carrying the attacker path.

```python
import urllib.parse
import urllib.request

AUTHZ = "https://idp.example/authorize"
BASE = {"response_type": "code", "client_id": "app",
        "redirect_uri": "https://app.example/oauth/callback", "state": "abc"}

def authorize(redirect_uri):
    params = dict(BASE, redirect_uri=redirect_uri)
    url = AUTHZ + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location", "")

control = authorize(BASE["redirect_uri"])
tampered = authorize(BASE["redirect_uri"] + "/../evil")
print({"control": control, "tampered": tampered,
       "loose_matching_suspected": tampered[0] in (302, 303) and "evil" in tampered[1]})
```
