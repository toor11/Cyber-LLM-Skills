# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-reflected`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sG 'https://target.example/search' --data-urlencode 'q=zz7q1<u>probe</u>'` | Capture the raw reflection and its surrounding context without a browser so the landing context is readable | Cross-platform |
| `Burp Suite Repeater` | `Send request to Repeater, toggle one delimiter, compare responses side by side` | Keeps the single-variable differential on one connection so only the changed delimiter moves | Cross-platform |
| `Playwright` | `npx playwright open 'https://target.example/search?q=zz7q1<u>probe</u>'` | Loads in real Chromium to confirm the marker became a DOM node rather than text | Cross-platform |
| `dalfox` | `dalfox url 'https://target.example/search?q=FUZZ' --no-color` | Context-aware reflected-XSS scanner that reports the landing context per parameter | Linux, macOS, Windows |

## Minimal Script Shape

A reflection-context classifier: it fetches the route with a unique marker and reports whether the marker reflected and in which HTML context it landed, so the right delimiter probe can be chosen.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/search"
MARKER = "zz7q1probe"

def fetch(value):
    url = BASE + "?" + urllib.parse.urlencode({"q": value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

body = fetch(MARKER)
idx = body.find(MARKER)
if idx < 0:
    print({"reflected": False})
else:
    window = body[max(0, idx - 40):idx]
    if "=\"" in window or "='" in window:
        context = "attribute"
    elif "<script" in window.lower():
        context = "script"
    else:
        context = "html-text"
    print({"reflected": True, "context": context, "preceding": window[-40:]})
```
