# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/?cdnprobe=1'` | Read the CDN cache-status and edge-identity headers to name the fronting product | Cross-platform |
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/p/report?lang=fr&cb=cdn-aaaa'` | Retrieve the colliding URL form and confirm a hit serving the other form's body | Cross-platform |
| `httpx` | `httpx -u https://target.example -title -tech-detect -include-response-header` | Enumerate edge headers to confirm the CDN and its cache-status field | Linux, Windows, macOS |
| `Burp Suite Repeater` | `Send the two URL forms repeatedly and watch cf-cache-status and Age for a shared entry` | Confirm cross-form key collision through one CDN POP | Cross-platform |

## Minimal Script Shape

A cross-form collision harness: it stores one language variant on a busted key, requests the other variant, and reports whether the edge served the first body from a hit.

```python
import urllib.request

EN = 'https://target.example/p/report?lang=en&cb=cdn-aaaa'
FR = 'https://target.example/p/report?lang=fr&cb=cdn-aaaa'

def fetch(url):
    r = urllib.request.Request(url, headers={'User-Agent': 'authorised-assessment'})
    with urllib.request.urlopen(r, timeout=10) as resp:
        status = (resp.headers.get('cf-cache-status')
                  or resp.headers.get('x-cache') or '')
        return status, resp.read().decode('utf-8', 'replace')[:200]

en_status, en_body = fetch(EN)
fr_status, fr_body = fetch(FR)
print({'en_status': en_status, 'fr_status': fr_status,
       'collision': (en_body == fr_body) and 'HIT' in fr_status.upper()})
```
