# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dom-based-vulnerabilities`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Browser DevTools` | `Set the fragment or query and read the live DOM` | Confirms the source reached a sink by inspecting the running document | Cross-platform |
| `ripgrep` | `rg -n -e innerHTML -e "document.write" -e "eval(" dist/` | Enumerates DOM sinks in the client bundle for source-to-sink tracing | Windows, Linux, macOS |
| `DOM Invader (Burp)` | `Enable DOM Invader and drive sources with the canary` | Shows which sinks receive the canary value across the page | Cross-platform |
| `Playwright` | `npx playwright open 'https://target.example/#zzd4k<u>probe</u>'` | Reproduces the source-to-sink flow and dumps outerHTML | Cross-platform |

## Minimal Script Shape

A static source-and-sink pairing scan: it lists DOM sources and sinks in a JavaScript file so each candidate flow can be traced, printing counts rather than exploiting anything.

```python
import re
import sys

SOURCES = [r"location\.hash", r"location\.search", r"document\.referrer",
           r"window\.name", r"\.data\b"]
SINKS = [r"innerHTML", r"document\.write", r"\beval\(", r"\.href\s*=",
         r"setAttribute\("]

def scan(path):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    src_hits = [(i + 1, l.strip()) for i, l in enumerate(lines)
                if any(re.search(p, l) for p in SOURCES)]
    sink_hits = [(i + 1, l.strip()) for i, l in enumerate(lines)
                 if any(re.search(p, l) for p in SINKS)]
    return src_hits, sink_hits

path = sys.argv[1] if len(sys.argv) > 1 else "app.js"
srcs, sinks = scan(path)
print({"sources": len(srcs), "sinks": len(sinks),
       "review": "trace each source to a sink" if srcs and sinks else "no obvious DOM flow"})
```
