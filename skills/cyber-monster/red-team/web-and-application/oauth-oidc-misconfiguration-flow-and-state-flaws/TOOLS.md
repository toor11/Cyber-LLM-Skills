# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`oauth-oidc-misconfiguration-flow-and-state-flaws`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Replay the callback with the state parameter cleared, then with a reused state` | Test one-time state binding without altering other parameters | Cross-platform |
| `curl` | `curl -sS -i -X POST 'https://idp.example/token' -d 'grant_type=authorization_code&code=<tester>&code_verifier=<v>'` | Attempt a token exchange with a verifier to probe for PKCE downgrade acceptance | Cross-platform |
| `jwt_tool` | `python jwt_tool.py <id_token>` | Read the id_token nonce and iss to design a replay or mix-up test | Cross-platform |
| `curl (OIDC discovery)` | `curl -sS -o oidc.json https://idp.example/.well-known/openid-configuration` | Save discovery, then search oidc.json for code_challenge_methods to see whether S256 PKCE is advertised | Cross-platform |

## Minimal Script Shape

A PKCE-downgrade harness: it posts a token exchange carrying a code_verifier where no challenge was registered and flags a probable downgrade if the server returns a success status.

```python
import urllib.parse
import urllib.request

TOKEN = "https://idp.example/token"

def exchange(params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(TOKEN, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "authorised-assessment")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

base = {"grant_type": "authorization_code", "code": "<tester-code>",
        "client_id": "app", "redirect_uri": "https://app.example/oauth/callback"}
with_verifier = exchange(dict(base, code_verifier="tester-verifier-no-challenge"))
print({"downgrade_exchange_status": with_verifier,
       "pkce_downgrade_suspected": with_verifier == 200})
```
