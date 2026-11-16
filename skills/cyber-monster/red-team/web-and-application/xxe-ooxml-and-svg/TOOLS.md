# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xxe-ooxml-and-svg`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `zip` | `zip -r crafted.docx [Content_Types].xml _rels word/` | Repack a document after editing the specific XML part to carry the DOCTYPE | Cross-platform |
| `oxml_xxe` | `java -jar oxml_xxe.jar` | Insert XXE payloads into office and SVG document parts for upload testing | Cross-platform |
| `interactsh-client` | `interactsh-client -v` | Observe out-of-band callbacks from a blind document-ingestion pipeline | Cross-platform |

## Minimal Script Shape

A document-part harness: it builds an in-memory docx whose word/document.xml carries a benign marker entity and reports whether a hardened parser rejects it.

```python
import io
import zipfile
import defusedxml.ElementTree as defused

MARKER = "xxeooxml-marker-8b4c"
PART = (
    "<!DOCTYPE d [<!ENTITY m '%s'>]>" % MARKER
    + "<document><body>&m;</body></document>"
).encode()

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as archive:
    archive.writestr("word/document.xml", PART)

with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as archive:
    inner = archive.read("word/document.xml")

try:
    defused.fromstring(inner, forbid_dtd=True)
    rejected = False
except Exception:  # noqa: BLE001  defused raises on a DTD
    rejected = True
print({"part_has_doctype": b"<!DOCTYPE" in inner, "hardened_parser_rejects": rejected})
```
