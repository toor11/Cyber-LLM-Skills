# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-fingerprinting-and-tech-detection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `whatweb` | `whatweb -a 3 https://target.example` | Aggregate header, cookie, and body signals into a weighted technology identification | Linux, Windows, macOS |
| `httpx` | `httpx -u https://target.example -tech-detect -server -title -favicon` | Collect the server header, detected technologies, and favicon hash in one pass | Linux, Windows, macOS |
| `curl` | `curl -sS -D - -o /dev/null https://target.example` | Read the raw response headers and cookie names to seed the passive fingerprint | Cross-platform |
| `nuclei` | `nuclei -u https://target.example -tags tech,favicon` | Match favicon and technology templates to corroborate a product identification | Cross-platform |

## Minimal Script Shape

A signal-collector: it gathers header and favicon-hash signals and reports whether at least two independent signals corroborate one identification.

```python
import hashlib
import urllib.request

BASE = 'https://target.example'

def get(path):
    r = urllib.request.Request(BASE + path, headers={'User-Agent': 'authorised-assessment'})
    with urllib.request.urlopen(r, timeout=10) as resp:
        return dict(resp.headers), resp.read()

root_headers, _ = get('/')
_, favicon = get('/favicon.ico')
signals = {
    'server': root_headers.get('Server', ''),
    'x_powered_by': root_headers.get('X-Powered-By', ''),
    'set_cookie': root_headers.get('Set-Cookie', '').split('=')[0],
    'favicon_md5': hashlib.md5(favicon).hexdigest(),
}
corroborated = sum(1 for v in signals.values() if v)
print({'signals': signals, 'independent_signals': corroborated,
       'confident': corroborated >= 2})
```
