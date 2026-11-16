# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-second-order`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite` | `Store value via the write request, then replay the read request from Repeater and diff responses` | Separate write and read so the deferred differential is attributed to the second path | Cross-platform |
| `psql client` | `SELECT name FROM users WHERE id = <self>;` | Confirm the stored value retains quote characters after the write before triggering the read | Linux, macOS, Windows |
| `ripgrep` | `rg -n -e ".format(" -e " + " --type py --type java` | Locate deferred queries that concatenate or format column values read back from the database | Cross-platform |

## Minimal Script Shape

A connectivity harness: it stores a unique marker through the write endpoint, then drives the suspected read endpoint and reports whether the stored value reaches the second path.

```python
import urllib.parse
import urllib.request

WRITE = "https://target.example/profile"
READ = "https://target.example/admin/review"

def send(url, field, value):
    data = urllib.parse.urlencode({field: value}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

marker = "probe_7f3a_marker"
send(WRITE, "display", marker)
read_body = send(READ, "noop", "")
print({"marker": marker, "stored_path_connected": marker in read_body})
```
