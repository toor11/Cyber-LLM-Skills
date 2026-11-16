# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`saml-assertion-attacks-assertion-forgery`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python3` | `python3 -c "import base64,sys; print(base64.b64decode(sys.argv[1]).decode())" "$SAMLResponse"` | Decode a captured response to edit NameID, Conditions, or the Signature for a forgery probe | Cross-platform |
| `SAML Raider` | `Use 'Remove Signatures' then edit NameID in the intercepted response` | Produce the unsigned and comment-split variants without manual base64 surgery | Cross-platform |
| `curl` | `curl -sS -i -X POST 'https://sp.example/acs' --data-urlencode 'SAMLResponse=...' --data-urlencode 'RelayState=/'` | Replay the forged or expired response to the Assertion Consumer Service and capture the decision | Cross-platform |
| `date` | `date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ'` | Compute a future timestamp to confirm whether NotOnOrAfter is enforced during a replay probe | Linux |

## Minimal Script Shape

A coverage-and-window inspector: it reports whether a response carries a ds:Signature and whether its Conditions NotOnOrAfter is still in the future, the two signals that separate a forgeable or replayable response from a sound one.

```python
import sys
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"


def inspect(path):
    root = ET.parse(path).getroot()
    has_sig = root.find(".//" + DS + "Signature") is not None
    cond = root.find(".//" + SAML + "Conditions")
    not_after = cond.get("NotOnOrAfter") if cond is not None else None
    return has_sig, not_after


if __name__ == "__main__":
    has_sig, not_after = inspect(sys.argv[1])
    expired = False
    if not_after:
        expired = datetime.now(timezone.utc) > datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    verdict = "signed and time-bounded" if has_sig and not_after and not expired else "forgery or replay exposed"
    print({"has_signature": has_sig, "not_on_or_after": not_after, "expired": expired}, verdict)
```
