# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xml-attacks-xxe-and-xslt`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `xsltproc` | `xsltproc --nonet style.xslt data.xml` | Run a transform locally with network disabled to observe document() and extension behaviour | Linux, macOS |
| `xmllint` | `xmllint --noout --xinclude --nonet doc.xml` | Test whether XInclude resolves while keeping network access off | Linux, macOS |
| `xcat` | `xcat --help` | Reference automation for confirming blind XPath injection differentials | Cross-platform |
| `python lxml` | `python3 -c "from lxml import etree; print(etree.LIBXSLT_VERSION)"` | Identify the XSLT engine version to know which capability functions exist | Cross-platform |

## Minimal Script Shape

An XPath structure-differential harness: it runs a true and a false predicate against a local XML document and flags injection when the two node sets differ.

```python
from lxml import etree

DOC = b"<users><user><name>alice</name></user><user><name>bob</name></user></users>"


def count(tree, value):
    # Unsafe concatenation mirrors the vulnerable sink under test.
    q = "//user[name/text()='%s']" % value
    return len(tree.xpath(q))


tree = etree.fromstring(DOC)
true_pred = count(tree, "alice' or '1'='1")
false_pred = count(tree, "alice' or '1'='2")
baseline = count(tree, "alice")
print({"baseline": baseline, "true_pred": true_pred, "false_pred": false_pred,
       "injectable": true_pred > baseline and true_pred != false_pred})
```
