# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`insecure-deserialization-php-gadgets`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `PHPGGC` | `phpggc -l` | Inventory known POP gadget chains available for the installed framework and version | Linux, macOS |
| `Semgrep` | `semgrep --config p/php -e 'unserialize(...)' .` | Find unserialize() calls on request data that omit the allowed_classes option | Cross-platform |
| `ripgrep` | `rg -n -e unserialize -e __wakeup -e __destruct -e phar .` | Map deserialization sinks and magic methods across the PHP codebase | Cross-platform |
| `Freddy (Burp extension)` | `Enable Freddy and submit an O:8:"stdClass":0:{} probe to the endpoint` | Detect whether the object string is deserialized by the handler | Cross-platform |

## Minimal Script Shape

A classifier that reports whether a value is a PHP object-serialization string, a scalar/array, or inert, so the unserialize sink and its allowed_classes posture can be reasoned about.

```python
import re, sys

OBJECT_RE = re.compile(r'^O:\d+:"[^"]+":\d+:\{')

def classify(value: str) -> str:
    if OBJECT_RE.match(value):
        return "php-object-serialization"
    if value.startswith("a:") or value.startswith("s:"):
        return "php-scalar-or-array"
    return "not-php-serialized"

for arg in sys.argv[1:]:
    v = classify(arg)
    print(repr(arg[:30]), "->", v)
    if v == "php-object-serialization":
        print("  object graph will instantiate; check allowed_classes => false")
```
