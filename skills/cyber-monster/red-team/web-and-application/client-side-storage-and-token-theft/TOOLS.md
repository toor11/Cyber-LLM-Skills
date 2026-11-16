# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`client-side-storage-and-token-theft`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Chrome DevTools` | `Application tab > Storage > Local Storage / IndexedDB / Cookies` | Enumerate stored tokens and read each cookie's HttpOnly flag | Cross-platform |
| `curl` | `curl -s https://target.example/static/main.js -o main.js` | Pull the shipped bundle so it can be scanned for baked-in secrets | Cross-platform |
| `trufflehog` | `trufflehog filesystem main.js` | Flag token-shaped secrets left in the JavaScript bundle by a wholesale env import | Linux, macOS, Windows |

## Minimal Script Shape

A bundle-secret harness: it fetches the shipped JavaScript and counts JWT- and key-shaped strings, reporting a possible leak without exfiltrating anything.

```python
import re
import urllib.request

BUNDLE = 'https://target.example/static/main.js'
PATTERNS = {
    'jwt_header': 'eyJ[A-Za-z0-9_-]{12,}',
    'assigned_secret': '(api|secret|token|key)[=:][A-Za-z0-9_-]{16,}',
}

req = urllib.request.Request(BUNDLE, headers={'User-Agent': 'authorised-assessment'})
with urllib.request.urlopen(req, timeout=10) as r:
    body = r.read().decode('utf-8', 'replace')

hits = {name: len(re.findall(pat, body)) for name, pat in PATTERNS.items()}
print({'bundle': BUNDLE, 'matches': hits,
       'possible_secret_leak': any(v > 0 for v in hits.values())})
```
