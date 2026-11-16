# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ldap-and-xpath-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ldapsearch` | `ldapsearch -x -H ldap://dir.example -b 'ou=people,dc=example,dc=com' '(uid=probe)'` | Reproduce how the directory evaluates a filter so the differential can be interpreted | Linux, macOS |
| `Semgrep` | `semgrep --config p/python -e 'conn.search(...)' .` | Find filters built by string concatenation rather than escaped values | Cross-platform |
| `Burp Intruder` | `Mark the username field and run a boolean-differential set of filter and XPath probes` | Compare result-set and status changes across benign and metacharacter inputs | Cross-platform |
| `ripgrep` | `rg -n -e "objectClass=" -e xpath -e XPathExpression -e evaluate .` | Locate LDAP filter and XPath construction sites in the code | Cross-platform |

## Minimal Script Shape

A metacharacter checker that reports whether a value carries LDAP or XPath breakout characters, indicating that escaping is required before it reaches a filter.

```python
import sys

LDAP_META = set("()&|!*=<>~")
XPATH_META = set("'[]/=()")

def classify(value: str) -> dict:
    return {"ldap_breakout": bool(set(value) & LDAP_META),
            "xpath_breakout": bool(set(value) & XPATH_META),
            "value": value[:20]}

for value in sys.argv[1:]:
    r = classify(value)
    needs = r["ldap_breakout"] or r["xpath_breakout"]
    print(r, "-> ESCAPE REQUIRED" if needs else "-> inert")
```
