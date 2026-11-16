# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jwt-attacks-header-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jwt_tool` | `python3 jwt_tool.py <token> -X i` | Inject a crafted kid and resend to test key-path resolution | Cross-platform |
| `jwt_tool` | `python3 jwt_tool.py <token> -X s -ju https://<assessor-controlled-host>/jwks.json` | Test jku redirection to an assessor-hosted JWKS | Cross-platform |
| `Burp JWT Editor` | `Use the embedded-JWK attack to add a jwk header with an attacker key` | Test whether the verifier trusts an inline key | Cross-platform |
| `interactsh-client` | `interactsh-client -v` | Catch the outbound jku or x5u fetch the server performs | Cross-platform |

## Minimal Script Shape

A header auditor that extracts kid, jku, x5u, and jwk and flags key sources that are external or embedded rather than server-controlled.

```python
import base64, json, sys
from urllib.parse import urlsplit

TRUSTED_HOSTS = {"idp.example"}

def header(token: str) -> dict:
    h = token.split(".")[0]
    pad = "=" * (-len(h) % 4)
    return json.loads(base64.urlsafe_b64decode(h + pad))

def flags(hdr: dict) -> dict:
    out = {}
    for field in ("jku", "x5u"):
        if field in hdr:
            host = urlsplit(hdr[field]).hostname
            out[field] = "UNTRUSTED" if host not in TRUSTED_HOSTS else "ok"
    if "jwk" in hdr:
        out["jwk"] = "embedded key - do not trust"
    if "kid" in hdr and any(c in hdr["kid"] for c in "/.'"):
        out["kid"] = "traversal or injection chars present"
    return out

for token in sys.argv[1:]:
    print(flags(header(token)))
```
