# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssti`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tplmap` | `tplmap -u 'https://target.example/greet?name=probe' --level 1` | Fingerprint the engine and confirm evaluation with arithmetic probes | Linux, macOS |
| `curl` | `curl -sS 'https://target.example/greet?name=%7B%7B7*7%7D%7D'` | Send the arithmetic probe and read whether the product is rendered | Cross-platform |
| `Semgrep` | `semgrep -e 'render_template_string($X)' --lang python .` | Find template APIs compiling request-derived strings | Cross-platform |

## Minimal Script Shape

An evaluation harness: it sends an arithmetic probe and a quoted control, then confirms SSTI only when the product appears for the probe but not the control.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/greet"

def render(name_value):
    url = BASE + "?" + urllib.parse.urlencode({"name": name_value})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

evaluated = render("{{7*7}}")
literal = render("{{'7*7'}}")
print({"evaluated_contains_49": "49" in evaluated,
       "control_contains_49": "49" in literal,
       "ssti_confirmed": "49" in evaluated and "49" not in literal})
```
