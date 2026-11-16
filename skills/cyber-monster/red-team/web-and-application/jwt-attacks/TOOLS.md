# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jwt-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jwt_tool` | `python3 jwt_tool.py <token> -M pb` | Run the playbook scan for alg:none, confusion, and missing claim checks | Cross-platform |
| `Burp JWT Editor` | `Load JWT Editor, decode the token, and resend with a modified header or claim` | Craft minimal non-destructive differentials (none, flipped byte, changed claim) | Cross-platform |
| `hashcat` | `hashcat -m 16500 token.txt wordlist.txt` | Attempt offline HMAC secret recovery when the token is HS-signed | Linux, Windows, macOS |

## Minimal Script Shape

A decoder that reads the unverified header and reports the algorithm and whether a signature is present, flagging the none and empty-signature cases.

```python
import base64, json, sys

def b64(part: str) -> dict:
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))

def inspect(token: str) -> dict:
    parts = (token.split(".") + ["", "", ""])[:3]
    header = b64(parts[0])
    alg = (header.get("alg") or "").lower()
    return {"alg": header.get("alg"), "signature_present": bool(parts[2]),
            "suspicious": alg == "none" or not parts[2]}

for token in sys.argv[1:]:
    print(inspect(token))
```
