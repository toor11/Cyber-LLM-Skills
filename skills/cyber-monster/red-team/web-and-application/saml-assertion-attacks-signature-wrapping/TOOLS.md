# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`saml-assertion-attacks-signature-wrapping`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `SAML Raider` | `Apply the XSW1 through XSW8 presets to the intercepted SAMLResponse` | Generate each standard wrapping layout so the position or ID selector can be fingerprinted | Cross-platform |
| `xmlsec1` | `xmlsec1 --verify --id-attr:ID {urn:oasis:names:tc:SAML:2.0:assertion}Assertion wrapped.xml` | Confirm the relocated signature still validates while the consumed node differs | Linux, macOS |
| `xmllint` | `xmllint --xpath 'count(//*[local-name()="Assertion"])' response.xml` | Count Assertion elements to detect injected or wrapped duplicates | Linux, macOS, Windows |
| `Burp Suite Repeater` | `Replay each wrapping variant to the Assertion Consumer Service on one connection` | Keep baseline and wrapped probe comparable for the Subject differential | Cross-platform |

## Minimal Script Shape

A position-versus-signed checker: it compares the first saml:Assertion ID against the ds:Reference targets so a service provider that selects by position rather than by the signed node is flagged.

```python
import sys
from xml.etree import ElementTree as ET

SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"


def analyse(path):
    root = ET.parse(path).getroot()
    assertions = root.findall(".//" + SAML + "Assertion")
    first_id = assertions[0].get("ID") if assertions else None
    refs = [r.get("URI", "").lstrip("#") for r in root.findall(".//" + DS + "Reference")]
    return first_id, refs, len(assertions)


if __name__ == "__main__":
    first_id, refs, n = analyse(sys.argv[1])
    position_matches_signed = first_id in refs
    verdict = "first assertion is the signed one" if n == 1 and position_matches_signed else "wrapping-exposed"
    print({"first_assertion_id": first_id, "signed_refs": refs, "assertion_count": n}, verdict)
```
