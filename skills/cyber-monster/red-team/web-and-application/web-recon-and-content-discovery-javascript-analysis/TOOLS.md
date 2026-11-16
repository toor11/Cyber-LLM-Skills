# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-recon-and-content-discovery-javascript-analysis`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `LinkFinder` | `python3 linkfinder.py -i https://target.example/static/js/main.js -o cli` | Extract endpoints and parameters embedded in a JavaScript chunk | Cross-platform |
| `trufflehog` | `trufflehog filesystem ./bundle --only-verified` | Scan downloaded chunks for secrets and keep only verified-live hits | Cross-platform |
| `source-map (CLI)` | `npx source-map-cli resolve main.<hash>.js.map` | Reconstruct original source files and paths from a shipped source map | Cross-platform |
| `httpx` | `httpx -u https://target.example/static/js/main.<hash>.js.map -status-code -content-length` | Confirm a source map is served and measure its size without downloading manually | Cross-platform |

## Minimal Script Shape

An endpoint-differential harness: it pulls a bundle, extracts API-looking paths, and prints which ones are absent from a supplied authenticated-baseline list.

```python
import re
import urllib.request

BUNDLE = "https://target.example/static/js/main.js"
BASELINE = {"/api/login", "/api/profile"}  # routes the app uses normally


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


body = fetch(BUNDLE)
found = set(re.findall(r"[\"']/(api/[A-Za-z0-9_/-]+)[\"']", body))
found = {"/" + p for p in found}
disclosed = sorted(found - BASELINE)
has_map = "//# sourceMappingURL=" in body
print({"endpoints_found": len(found), "build_disclosed": disclosed,
       "source_map_referenced": has_map})
```
