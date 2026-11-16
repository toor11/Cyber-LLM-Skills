# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jndi-injection-logging-lookups`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `interactsh-client` | `interactsh-client -v` | Capture the DNS or JNDI callback produced when a logged header is interpolated | Cross-platform |
| `logpresso log4j2-scan` | `log4j2-scan /path/to/app` | Inventory log4j-core jars and flag versions whose JndiLookup resolver is still present | Cross-platform |
| `ripgrep` | `rg -n -e "logger.info" -e "logger.warn" -e "logger.error" -e getHeader -e getParameter .` | Find logging calls and request-value accessors that may interpolate attacker-controlled input | Cross-platform |
| `curl` | `curl -s -A 'probe-${env:USER}' https://target.example/` | Send a benign non-jndi lookup in a logged header to test interpolation safely | Cross-platform |

## Minimal Script Shape

A scanner that flags whether a header value carries a log4j lookup expression, so a logging sink can be reasoned about before any jndi callback is attempted.

```python
import re, sys

LOOKUP = re.compile(r"\$\{[^}]*(jndi|lower|upper|env|sys|date|java)[^}]*", re.I)

def classify(value: str) -> str:
    if LOOKUP.search(value):
        return "contains log4j lookup expression"
    if "${" in value:
        return "contains template marker (inspect layout)"
    return "literal"

for arg in sys.argv[1:]:
    verdict = classify(arg)
    print(repr(arg), "->", verdict)
    if "lookup" in verdict:
        print("  logger will evaluate this unless formatMsgNoLookups is set")
```
