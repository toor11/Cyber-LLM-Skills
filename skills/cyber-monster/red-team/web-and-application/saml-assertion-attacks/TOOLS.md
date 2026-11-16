# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`saml-assertion-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `SAML Raider` | `Intercept the SAMLResponse in Burp and apply the 'Remove Signatures' and XSW presets` | Produce signature-presence and wrapping differentials from a captured response without hand-editing XML | Cross-platform |
| `xmlsec1` | `xmlsec1 --verify --id-attr:ID Assertion response.xml` | Confirm which element a signature actually covers so a parser differential can be demonstrated | Linux, macOS |
| `python3` | `python3 -c "import base64,sys; print(base64.b64decode(sys.argv[1]).decode())" "$SAMLResponse"` | Decode the SAMLResponse to inspect Assertion, Signature, and Conditions before probing | Cross-platform |
| `curl` | `curl -sS -i -X POST 'https://sp.example/acs' --data-urlencode 'SAMLResponse=...' --data-urlencode 'RelayState=/'` | Replay an edited response to the Assertion Consumer Service and read the accept or reject decision | Cross-platform |

## Minimal Script Shape

An assertion-and-reference inspector: it counts saml:Assertion elements and checks whether each ds:Reference URI matches an assertion ID, flagging responses where the signed element and the consumed one may diverge.

```python
import sys
from xml.etree import ElementTree as ET

SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"


def inspect(path):
    doc = ET.parse(path).getroot()
    assertions = doc.findall(".//" + SAML + "Assertion")
    refs = [r.get("URI", "").lstrip("#") for r in doc.findall(".//" + DS + "Reference")]
    ids = [a.get("ID") for a in assertions]
    return assertions, refs, ids


if __name__ == "__main__":
    assertions, refs, ids = inspect(sys.argv[1])
    single = len(assertions) == 1
    covered = bool(refs) and all(r in ids for r in refs)
    verdict = "signed element matches the only assertion" if single and covered else "parser-differential risk"
    print({"assertions": len(assertions), "references": refs, "ids": ids}, verdict)
```
