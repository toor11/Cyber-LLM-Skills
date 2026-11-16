# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xml-attacks-xxe-and-xslt-xslt-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `xsltproc` | `xsltproc --nonet suspect.xslt data.xml` | Compile a candidate stylesheet with network off to observe document() and extension behaviour | Linux, macOS |
| `Saxon-HE` | `java -jar saxon-he.jar -xsl:suspect.xslt -s:data.xml -it` | Run the transform on Saxon to enumerate which extension functions are available | Cross-platform |
| `python lxml` | `python3 -c "from lxml import etree; print(etree.LIBXSLT_VERSION)"` | Report the libxslt version so known capability functions can be mapped | Cross-platform |

## Minimal Script Shape

A capability-reflection harness: it runs a benign system-property stylesheet and reports XSLT injection when engine metadata appears in the output.

```python
from lxml import etree

DATA = etree.XML("<r/>")
PROBE = (
    "<xsl:stylesheet version='1.0' "
    "xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>"
    "<xsl:template match='/'>"
    "<out><xsl:value-of select=\"system-property('xsl:vendor')\"/></out>"
    "</xsl:template></xsl:stylesheet>"
)


def run(style_text):
    style = etree.XSLT(etree.XML(style_text))
    return str(style(DATA))


result = run(PROBE)
leaked = "libxslt" in result.lower() or "saxon" in result.lower() or "xalan" in result.lower()
print({"output": result.strip()[:80], "capability_reflected": leaked})
```
