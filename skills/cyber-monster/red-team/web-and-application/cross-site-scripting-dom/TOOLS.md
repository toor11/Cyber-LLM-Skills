# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-dom`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `DOM Invader` | `enable DOM Invader in the Burp embedded browser and set the canary` | Trace DOM sources to sinks automatically and flag innerHTML and eval reach | Cross-platform |
| `Playwright` | `npx playwright open 'https://target.example/#domProbe42'` | Drive the hash source in a real browser and watch the sink element render | Cross-platform |
| `ripgrep` | `rg -n -e "location.hash" -e "location.search" -e "document.referrer" -e innerHTML -e "document.write" -e postMessage app.js` | Inventory candidate DOM sources and sinks in the client bundle before tracing | Cross-platform |

## Minimal Script Shape

A static source-to-sink scan: it fetches a script bundle and reports whether both a DOM taint source and a string-to-markup or code sink are present, flagging a flow to trace in a browser.

```python
import re
import urllib.request

BUNDLE = "https://target.example/static/app.js"

with urllib.request.urlopen(BUNDLE, timeout=10) as r:
    js = r.read().decode("utf-8", "replace")

SOURCES = ["location.hash", "location.search", "document.referrer", "postMessage"]
SINKS = ["innerHTML", "outerHTML", "document.write", "eval("]
found_sources = [s for s in SOURCES if s in js]
found_sinks = [s for s in SINKS if re.search(re.escape(s), js)]
# both a taint source and a markup/code sink in one bundle flags a DOM flow
print({"sources": found_sources, "sinks": found_sinks,
       "candidate_dom_flow": bool(found_sources) and bool(found_sinks)})
```
