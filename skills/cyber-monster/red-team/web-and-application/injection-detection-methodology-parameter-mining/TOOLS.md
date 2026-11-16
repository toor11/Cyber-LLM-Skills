# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`injection-detection-methodology-parameter-mining`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Arjun` | `arjun -u 'https://target.example/api/search' -m GET -oT arjun.txt` | Add candidate parameters one at a time and report which produce a response differential | Linux, macOS, Windows |
| `Burp Suite Param Miner` | `Right-click request, 'Guess query parameters' and 'Guess headers'` | Mine both query and header name spaces using the extension's built-in differential checks | Cross-platform |
| `ffuf` | `ffuf -u 'https://target.example/api/search?FUZZ=1' -w params.txt -mc all -fs 0` | Fuzz candidate parameter names and filter by response size to surface consumed keys | Linux, macOS, Windows |
| `LinkFinder` | `python3 linkfinder.py -i https://target.example/app.js -o cli` | Extract endpoint and parameter names from JavaScript bundles as mining candidates | Linux, macOS |

## Minimal Script Shape

A parameter-mining harness: it fetches a baseline, then adds each candidate parameter individually and reports those whose response size or status differs from the baseline, which marks a likely consumed hidden input.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/api/search"
KNOWN = {"q": "test"}
CANDIDATES = ["debug", "admin", "include_drafts", "format", "callback"]

def fetch(params):
    url = BASE + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, len(r.read())

base = fetch(KNOWN)
consumed = []
for name in CANDIDATES:
    trial = dict(KNOWN)
    trial[name] = "1"
    status, size = fetch(trial)
    if status != base[0] or abs(size - base[1]) > 32:
        consumed.append({"param": name, "status": status, "size": size})
print({"baseline": base, "likely_consumed": consumed})
```
