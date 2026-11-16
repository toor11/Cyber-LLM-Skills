# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`clickjacking-and-ui-redressing`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sI https://target.example/account/settings` | Read whether the response carries X-Frame-Options or a CSP frame-ancestors directive | Cross-platform |
| `Burp Suite Clickbandit` | `Burp > target tab > Clickbandit, record an overlay against the authorised page` | Generate a framing proof so the composited click path is visible without hand-writing HTML | Cross-platform |
| `Playwright` | `npx playwright open https://assessor.example/frame-test.html` | Load the target inside a cross-origin frame in a real Chromium to confirm the browser honours or ignores the framing header | Cross-platform |

## Minimal Script Shape

A framing-policy harness: it fetches the target's headers and decides whether classic framing is possible, prompting the DoubleClickjacking top-level fork when headers are present.

```python
import urllib.request

TARGET = 'https://target.example/account/settings'

def framing_headers(url):
    req = urllib.request.Request(url, method='HEAD',
                                 headers={'User-Agent': 'authorised-assessment'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return {k.lower(): v for k, v in r.headers.items()}

h = framing_headers(TARGET)
xfo = h.get('x-frame-options', '')
csp = h.get('content-security-policy', '')
frame_ancestors = 'frame-ancestors' in csp.lower()
framable = not xfo and not frame_ancestors
print({'x_frame_options': xfo, 'frame_ancestors_present': frame_ancestors,
       'classic_clickjacking_possible': framable,
       'note': 'if False, test the DoubleClickjacking top-level fork'})
```
