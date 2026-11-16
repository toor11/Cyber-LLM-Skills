# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Playwright` | `npx playwright open https://target.example` | Render the injected marker in a real browser so execution, not reflection, is observed | Cross-platform |
| `Dalfox` | `dalfox url 'https://target.example/search?q=zqxMarker1'` | Classify the reflection context and confirm a context-matched break | Linux, macOS, Windows |
| `curl` | `curl -sS 'https://target.example/search?q=%3CzqxMarker1%3E'` | Capture the raw server response to see whether angle brackets are encoded at the sink | Cross-platform |

## Minimal Script Shape

A reflection-context classifier: it sends a marker in angle brackets and reports whether the brackets survive unencoded, which indicates an HTML-context sink that needs a browser execution check.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/search"
MARKER = "zqxMarker1"

def body_for(payload):
    url = BASE + "?" + urllib.parse.urlencode({"q": payload})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

raw = body_for("<" + MARKER + ">")
html_context = ("<" + MARKER + ">") in raw
entity_encoded = ("&lt;" + MARKER) in raw
# Unencoded angle brackets flag an HTML-context sink to confirm in a browser
print({"html_context_open": html_context, "entity_encoded": entity_encoded,
       "needs_browser_confirm": html_context and not entity_encoded})
```
