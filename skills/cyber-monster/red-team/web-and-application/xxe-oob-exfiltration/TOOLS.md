# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`xxe-oob-exfiltration`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `interactsh-client` | `interactsh-client -v` | Receive DNS and HTTP callbacks with source address and any carried marker data | Cross-platform |
| `Burp Collaborator` | `Generate a Collaborator host, host the external DTD, then poll the Collaborator tab` | Serve the external DTD and observe the data-carrying callback in one place | Cross-platform |
| `python http.server` | `python3 -m http.server 8000` | Host the benign external DTD on an assessor-controlled endpoint for the parser to fetch | Cross-platform |

## Minimal Script Shape

A callback-attribution helper: it serves no payload but checks a captured callback log for the benign marker and reports exfiltration only when data, not just a lookup, is present.

```python
import json

MARKER = "xxeoob-marker-3d9f"

# Each record is one captured callback from the assessor listener.
callbacks = [
    {"proto": "dns", "host": "xxeoob-ping.assessor.example", "data": ""},
    {"proto": "http", "host": "assessor.example", "data": "d=" + MARKER},
]


def verdict(records):
    carried = [r for r in records if MARKER in r.get("data", "")]
    resolved_only = [r for r in records if not r.get("data")]
    return {
        "data_bearing_callbacks": len(carried),
        "resolution_only": len(resolved_only),
        "exfiltration_proven": bool(carried),
    }


print(json.dumps(verdict(callbacks)))
```
