# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`open-redirect`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null "https://target.example/login?next=//assessor.example"` | Print the response headers so the Location host is visible without following the redirect | Cross-platform |
| `Burp Suite Repeater` | `Send the redirecting request to Repeater and edit the next / returnUrl value per probe` | Compare the 30x status and Location value across destination forms on one connection | Cross-platform |
| `nuclei` | `nuclei -u https://target.example -tags redirect -severity info,low,medium` | Run community open-redirect templates across the discovered parameter set | Cross-platform |

## Minimal Script Shape

A destination classifier: it parses each candidate value and reports whether it carries off-site authority and whether it is a member of the same-site path allowlist.

```python
import sys
from urllib.parse import urlsplit

SAFE_PATHS = {"/", "/dashboard", "/account"}

def verdict(value):
    parts = urlsplit(value)
    off_site = bool(parts.scheme or parts.netloc) or value.startswith("//")
    allowed = (not off_site) and value in SAFE_PATHS
    return {"target": value, "off_site": off_site, "allowed_by_map": allowed}

for candidate in sys.argv[1:]:
    row = verdict(candidate)
    print(row, "OPEN-REDIRECT" if row["off_site"] else "same-site")
```
