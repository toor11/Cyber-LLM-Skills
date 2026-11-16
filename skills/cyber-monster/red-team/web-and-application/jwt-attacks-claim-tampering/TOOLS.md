# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jwt-attacks-claim-tampering`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jwt_tool` | `python3 jwt_tool.py <token> -T` | Tamper exp, aud, and iss interactively and resubmit to test enforcement | Cross-platform |
| `Burp JWT Editor` | `Decode the token, edit the exp, aud, or iss claims, and replay the request` | Observe whether a stale or mis-audienced token is still accepted | Cross-platform |
| `jwt-cli` | `jwt decode <token>` | Read exp, aud, iss, and iat to compare against the server's enforcement | Cross-platform |

## Minimal Script Shape

A payload auditor that reports whether a token carries exp, aud, and iss and whether it is already expired, so missing lifecycle checks can be targeted.

```python
import base64, json, sys, time

def payload(token: str) -> dict:
    p = token.split(".")[1]
    pad = "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p + pad))

def audit(claims: dict) -> dict:
    now = int(time.time())
    return {"has_exp": "exp" in claims,
            "expired": claims.get("exp", now + 1) < now,
            "has_aud": "aud" in claims,
            "has_iss": "iss" in claims}

for token in sys.argv[1:]:
    print(audit(payload(token)))
```
