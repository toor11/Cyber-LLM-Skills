# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-csp-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `CSP Evaluator` | `paste the Content-Security-Policy value into the Google CSP Evaluator` | Flag host-allowlist weaknesses and missing base-uri or object-src directives | Cross-platform |
| `curl` | `curl -sS -D - -o /dev/null https://target.example/` | Read the raw Content-Security-Policy header to classify its structural shape | Cross-platform |
| `Playwright` | `npx playwright open https://target.example` | Observe whether a gadget-loaded script runs while inline script is blocked and reported | Cross-platform |

## Minimal Script Shape

A policy-shape classifier: it reads the deployed CSP and reports whether execution is gated by a host allowlist and whether base-uri and form-action are set, which decides if allowlist gadgets apply.

```python
import urllib.request

ENDPOINT = "https://target.example/"

with urllib.request.urlopen(ENDPOINT, timeout=10) as r:
    csp = r.headers.get("Content-Security-Policy", "")

directives = {}
for part in csp.split(";"):
    part = part.strip()
    if part:
        name, _, value = part.partition(" ")
        directives[name.lower()] = value

script_src = directives.get("script-src", "")
host_allowlisted = "http" in script_src
nonce_dynamic = "'strict-dynamic'" in script_src and "nonce-" in script_src
print({"script_src": script_src, "form_action_set": "form-action" in directives,
       "base_uri_set": "base-uri" in directives,
       "host_allowlist_gadgets_apply": host_allowlisted and not nonce_dynamic})
```
