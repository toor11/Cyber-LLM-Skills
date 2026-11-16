# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`oauth-oidc-misconfiguration-token-and-scope-abuse`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -H 'Authorization: Bearer <token-aud-clientA>' 'https://api.b.example/v1/orders'` | Replay a token at a resource server that should reject its audience | Cross-platform |
| `jwt_tool` | `python jwt_tool.py <access_token>` | Read the aud, iss, and scope claims to design substitution and scope tests | Cross-platform |
| `curl (introspection)` | `curl -sS -X POST 'https://idp.example/introspect' -d 'token=<access_token>'` | Compare the authorization server's view of scope and audience with what the resource enforces | Cross-platform |
| `Burp Suite Repeater` | `Resend a protected request swapping the bearer token between two controlled clients` | Isolate audience validation by changing only the token | Cross-platform |

## Minimal Script Shape

A cross-client audience harness: it calls a protected API with a token minted for this resource and then with a token minted for another client, flagging a missing audience check if both succeed.

```python
import urllib.request

API = "https://api.b.example/v1/orders"

def call(token):
    req = urllib.request.Request(API)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("User-Agent", "authorised-assessment")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

own_audience = call("<token-aud-clientB>")
foreign_audience = call("<token-aud-clientA>")
print({"own_audience_status": own_audience,
       "foreign_audience_status": foreign_audience,
       "missing_audience_check": foreign_audience == own_audience == 200})
```
