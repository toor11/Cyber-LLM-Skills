# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cors-misconfiguration-reflected-origin`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/api/session' -H 'Origin: https://shop.example.com.reflect-probe.test'` | Check whether a suffix-match lookalike Origin is reflected into the allow-origin header | Cross-platform |
| `CORScanner` | `python cors_scan.py -u https://target.example/api/session -v` | Enumerate reflected-origin, prefix, suffix, and null trust conditions in one pass | Cross-platform |
| `Burp Suite Intruder` | `Load the lookalike Origin list into the Origin header position` | Sweep operator-specific lookalike origins and record which are reflected | Cross-platform |

## Minimal Script Shape

A lookalike-origin harness: it sends suffix, prefix, substring, and null Origins and reports which are reflected, pinpointing the weak matching operator.

```python
import urllib.request

ENDPOINT = "https://target.example/api/session"

def reflects(origin):
    req = urllib.request.Request(ENDPOINT, headers={"Origin": origin})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.headers.get("Access-Control-Allow-Origin") == origin

probes = {
    "suffix": "https://shop.example.com.reflect-probe.test",
    "prefix": "https://shop.example.com.reflectprobe",
    "substring": "https://reflectprobe-example.com",
    "null": "null",
}
results = {name: reflects(origin) for name, origin in probes.items()}
# Any True identifies a substring, prefix, suffix, or null flaw rather than an exact set
print({"reflections": results, "weak_match": any(results.values())})
```
