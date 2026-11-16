# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`csp-and-security-header-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sI https://target.example/app` | Read the CSP and related headers exactly as served | Cross-platform |
| `Google CSP Evaluator` | `Paste the policy into the CSP Evaluator web tool` | Enumerates unsafe-inline, missing base-uri/object-src, and gadget-prone hosts | Cross-platform |
| `nuclei` | `nuclei -u https://target.example -t http/misconfiguration/ -nc` | Flags missing or weak security headers across routes at scale | Linux, Windows, macOS |
| `Browser DevTools` | `Open the console and read CSP violations and report-to payloads` | Confirms which construct the live policy allowed or blocked | Cross-platform |

## Minimal Script Shape

A policy-weakness checker: it fetches the route twice, parses the CSP, flags permissive or missing directives, and compares nonces across the two fetches.

```python
import re
import urllib.request

URL = "https://target.example/app"

def fetch():
    req = urllib.request.Request(URL, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.headers.get("Content-Security-Policy", "")

csp1 = fetch()
csp2 = fetch()
directives = {p.strip().split(" ")[0]: p.strip() for p in csp1.split(";") if p.strip()}
weak = []
if "'unsafe-inline'" in directives.get("script-src", ""):
    weak.append("script-src unsafe-inline")
for req_dir in ("base-uri", "object-src", "form-action"):
    if req_dir not in directives:
        weak.append("missing " + req_dir)
n1 = re.findall(r"nonce-[A-Za-z0-9_-]+", csp1)
n2 = re.findall(r"nonce-[A-Za-z0-9_-]+", csp2)
if n1 and n1 == n2:
    weak.append("nonce reused across responses")
print({"weak_points": weak or ["none observed"], "policy": csp1[:120]})
```
