# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jwt-attacks-algorithm-confusion`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jwt_tool` | `python3 jwt_tool.py <token> -X k -pk public.pem` | Perform the RS256-to-HS256 key-confusion test using the published public key | Cross-platform |
| `jwt_tool` | `python3 jwt_tool.py <token> -X a` | Test alg:none acceptance across casings | Cross-platform |
| `openssl` | `openssl rsa -pubin -in jwks_key.pem -text -noout` | Extract and confirm the RSA public key material to reuse as the HMAC-secret probe | Cross-platform |
| `Burp JWT Editor` | `Use the Sign tab with HS256 and paste the public key as the secret` | Reproduce the confusion inside the proxy for the differential | Cross-platform |

## Minimal Script Shape

A classifier that reads the unverified header alg and reports whether the token is symmetric (confusion risk if a public key is also held), asymmetric, or none.

```python
import base64, json, sys

def header(token: str) -> dict:
    h = token.split(".")[0]
    pad = "=" * (-len(h) % 4)
    return json.loads(base64.urlsafe_b64decode(h + pad))

def verdict(alg: str) -> str:
    a = (alg or "").lower()
    if a == "none":
        return "alg:none - no verification"
    if a.startswith("hs"):
        return "symmetric - confusion risk if server also holds a public key"
    if a.startswith(("rs", "es", "ps")):
        return "asymmetric - forgery needs key confusion or header injection"
    return "unknown alg"

for token in sys.argv[1:]:
    alg = header(token).get("alg")
    print(alg, "->", verdict(alg))
```
