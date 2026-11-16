# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xxe`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST --data-binary @probe.xml -H 'Content-Type: application/xml' https://target.example/import` | Submit the XML probe and capture whether the entity reflects in the response | Cross-platform |
| `interactsh-client` | `interactsh-client -v` | Collect out-of-band callbacks with the source address to prove the server issued the fetch | Cross-platform |
| `xmllint` | `xmllint --noent --nonet probe.xml` | Confirm locally whether a parser with entities on would dereference the declaration | Linux, macOS |

## Minimal Script Shape

A parser-configuration checker: it parses a benign-entity document once with entity resolution on and once off, reporting whether the entity dereferences.

```python
from lxml import etree

DOC = (
    b"<!DOCTYPE xxe [<!ENTITY probe 'xxe-core-marker-1a2b'>]>"
    b"<root>&probe;</root>"
)


def expands(resolve):
    parser = etree.XMLParser(resolve_entities=resolve, load_dtd=resolve,
                             no_network=True)
    try:
        root = etree.fromstring(DOC, parser)
        return (root.text or "")
    except etree.XMLSyntaxError:
        return ""


vulnerable = "xxe-core-marker-1a2b" in expands(True)
hardened = "xxe-core-marker-1a2b" in expands(False)
print({"resolves_when_on": vulnerable, "resolves_when_off": hardened,
       "verdict": "entity processing enabled" if vulnerable else "inert"})
```
