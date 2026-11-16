# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' 'https://target.example/orders?sort=created_at'` | Capture the status, body size, and elapsed-time triple that forms the baseline for every differential | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/orders?sort=created_at' --batch --level=1 --risk=1 --technique=B` | Confirm a boolean channel with the least intrusive technique set; `--technique=B` avoids stacked and file primitives | Linux, Windows, macOS |
| `Semgrep` | `semgrep --config p/sql-injection --severity ERROR .` | Source-to-sink taint pass that finds interpolated statements and raw ORM fragments before runtime testing | Cross-platform |
| `Burp Suite Repeater` | `Send to Repeater, then use 'Send group in sequence (single connection)' for the paired baseline` | Keeps the confirmation pair on one connection so connection setup does not pollute timing | Cross-platform |

## Minimal Script Shape

A paired-baseline harness: two benign literals establish the noise band, then one boundary literal is compared against it. It reports a differential only when the probe moves outside the band.

```python
import statistics
import urllib.parse
import urllib.request

BASE = "https://target.example/orders"
PARAM = "sort"

def fetch(value):
    url = BASE + "?" + urllib.parse.urlencode({PARAM: value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read()
        return r.status, len(body)

control_a = fetch("created_at")
control_b = fetch("id")
noise = abs(control_a[1] - control_b[1])

probe = fetch("__unknown_column__")
delta = abs(probe[1] - control_a[1])
print({"control_a": control_a, "control_b": control_b,
       "noise_band": noise, "probe": probe, "delta": delta,
       "differential": delta > max(noise, 32)})
```
