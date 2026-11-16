# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`graphql-security-batching-and-dos`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' -X POST https://target.example/graphql -H 'Content-Type: application/json' -d @aliased.json` | Measure latency of a small aliased query against a baseline | Cross-platform |
| `graphql-cop` | `graphql-cop -t https://target.example/graphql` | Check for batching, alias, and depth-limit configuration | Linux, macOS, Windows |
| `Burp Suite Repeater` | `Send a single operation then a lightly aliased one to compare timing` | Run the multiplier differential on one connection | Cross-platform |

## Minimal Script Shape

A multiplier-timing harness: it times a single-field query against a lightly aliased one and reports whether latency scales with the alias count, indicating no cost cap.

```python
import json, sys, time, urllib.request

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/graphql"

def timed(query):
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "authorised-assessment"})
    start = time.time()
    with urllib.request.urlopen(req, timeout=20) as r:
        r.read()
    return time.time() - start

baseline = timed("{ a: __typename }")
aliased = timed("{ " + " ".join("a%d: __typename" % i for i in range(25)) + " }")
print({"baseline_s": round(baseline, 3), "aliased_s": round(aliased, 3),
       "scales_with_aliases": aliased > baseline * 3})
```
