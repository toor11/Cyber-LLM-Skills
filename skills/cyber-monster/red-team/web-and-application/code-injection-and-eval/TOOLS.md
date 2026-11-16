# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`code-injection-and-eval`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -G 'https://target.example/metric' --data-urlencode 'formula=668+669'` | Submit the arithmetic differential and read whether the computed value returns in the body | Cross-platform |
| `Semgrep` | `semgrep --config p/command-injection --severity ERROR .` | Taint pass that locates eval, assert, create_function, and Function sinks fed by request data | Cross-platform |
| `ripgrep` | `rg -n -e "\beval\s*\(" -e "\bassert\s*\(" -e "\bcreate_function\s*\(" -e "\bScriptEngine\s*\(" --type-add "web:*.{php,py,js,java}" -t web` | Inventory candidate evaluator call sites across a mixed-language codebase before runtime probing | Cross-platform |

## Minimal Script Shape

An arithmetic-reflection harness: it sends an inert literal and a benign product, then reports whether the server returned the computed value, which only a live evaluator would do.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/metric"

def send(formula):
    url = BASE + "?" + urllib.parse.urlencode({"formula": formula})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace").strip()

inert = send("1337")
probe = send("191*7")
# If the evaluator computed 191*7 the two bodies converge on 1337
print({"inert_literal": inert[:40], "product_probe": probe[:40],
       "evaluator_reachable": probe == inert})
```
