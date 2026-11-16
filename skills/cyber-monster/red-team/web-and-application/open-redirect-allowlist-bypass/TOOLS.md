# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`open-redirect-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null "https://target.example/go?redirect=https://target.example@assessor.example/"` | Reveal whether a userinfo authority form passes the allowlist by inspecting the Location header | Cross-platform |
| `Burp Suite Intruder` | `Load an encoding and authority wordlist into the redirect parameter position` | Sweep suffix, userinfo, and encoded forms to find which the comparison accepts | Cross-platform |
| `python` | `python bypass_check.py https://target.example@assessor.example/` | Compare the suffix-match verdict against exact-membership to localise the gap | Cross-platform |

## Minimal Script Shape

A comparison differential: for each candidate it reports the suffix-match verdict and the exact-membership verdict, flagging values that a loose guard accepts but an exact guard rejects.

```python
import sys
from urllib.parse import urlsplit

ALLOWED = {"target.example", "www.target.example"}

def check(url):
    host = (urlsplit(url).hostname or "").lower()
    suffix_ok = host.endswith("target.example")
    exact_ok = host in ALLOWED
    return {"url": url, "host": host, "suffix_match": suffix_ok, "exact_match": exact_ok,
            "bypasses_suffix_guard": suffix_ok and not exact_ok}

for arg in sys.argv[1:]:
    print(check(arg))
```
