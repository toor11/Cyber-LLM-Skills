# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`insecure-deserialization-python-and-ruby-gadgets`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Bandit` | `bandit -r . -t B301,B403,B506` | Flag pickle (B301/B403) and yaml.load (B506) unsafe deserialization sinks in Python code | Cross-platform |
| `Brakeman` | `brakeman -A -q` | Detect Marshal.load and YAML.load on untrusted input in a Rails codebase | Cross-platform |
| `Semgrep` | `semgrep --config p/python -e 'pickle.loads(...)' .` | Locate pickle.loads and yaml.load sinks reachable from request data | Cross-platform |
| `ripgrep` | `rg -n -e "pickle.loads" -e "yaml.load" -e "Marshal.load" .` | Map Python and Ruby object-reconstruction sinks across the repository | Cross-platform |

## Minimal Script Shape

A byte-signature classifier that names the serialization format behind a value (pickle, Ruby Marshal, unsafe YAML tag, or inert) so the loader can be identified before any object is sent.

```python
import base64, sys

def classify(raw: bytes) -> str:
    if raw[:1] == b"\x80":
        return "python-pickle (proto 2+)"
    if raw[:2] == b"\x04\x08":
        return "ruby-marshal"
    text = raw.decode("utf-8", "ignore")
    if "!!python/object" in text or "!!ruby/object" in text:
        return "unsafe-yaml-tag"
    return "inert-data"

for arg in sys.argv[1:]:
    try:
        raw = base64.b64decode(arg)
    except Exception:
        raw = arg.encode()
    print(repr(arg[:24]), "->", classify(raw))
```
