# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`injection-detection-methodology`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' 'https://target.example/search?q=probe'` | Capture the status, size, and time triple that forms the baseline for every channel differential | Cross-platform |
| `Burp Suite Intruder` | `Load a boundary-character list and run a sniper attack on one parameter at a time` | Drive one structure-changing probe per request so any differential is attributable to that character | Cross-platform |
| `ffuf` | `ffuf -u 'https://target.example/search?q=FUZZ' -w boundaries.txt -mc all -of json` | Record status and length per probe so channel differentials are machine-comparable | Linux, macOS, Windows |
| `interactsh-client` | `interactsh-client -v` | Provide an out-of-band oracle for inputs where no in-band channel survives | Cross-platform |

## Minimal Script Shape

A multi-channel differential harness: it fetches a benign baseline and a structure-changing probe for one parameter and reports which channel diverged (status, length, or timing) beyond a two-sample noise band, so the input can be routed to the right class.

```python
import time
import urllib.parse
import urllib.request

BASE = "https://target.example/search"
PARAM = "q"

def fetch(value):
    url = BASE + "?" + urllib.parse.urlencode({PARAM: value})
    start = time.monotonic()
    with urllib.request.urlopen(url, timeout=10) as r:
        body = r.read()
    return r.status, len(body), time.monotonic() - start

base_a = fetch("probe")
base_b = fetch("proba")
noise = abs(base_a[1] - base_b[1])
probe = fetch("probe'\"<")
print({"baseline_a": base_a, "baseline_b": base_b, "probe": probe,
       "length_channel": abs(probe[1] - base_a[1]) > max(noise, 32),
       "status_channel": probe[0] != base_a[0]})
```
