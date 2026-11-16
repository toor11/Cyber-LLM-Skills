# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`open-redirect-chain-to-token-theft`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite` | `Proxy the full authorization flow and watch the /callback and token requests` | Observe where the code or token appears and whether any hop carries it off-origin | Cross-platform |
| `curl` | `curl -sS -D - -o /dev/null "https://idp.example/authorize?response_type=code&redirect_uri=https://app.example/callback/forward?to=assessor.example"` | Check whether a registered-prefix extension is accepted by the authorization server | Cross-platform |
| `python` | `python redirect_uri_check.py https://app.example/callback/forward?to=assessor.example` | Compare prefix acceptance against exact registration for a candidate redirect_uri | Cross-platform |

## Minimal Script Shape

A redirect_uri matcher: it contrasts prefix acceptance with exact registration so a candidate that only a prefix check would admit is flagged as a code-theft risk.

```python
import sys

REGISTERED = ["https://app.example/callback"]

def classify(candidate):
    # Prefix acceptance is the classic open-redirect-to-code-leak opening
    prefix_ok = any(candidate.startswith(r) for r in REGISTERED)
    exact_ok = candidate in REGISTERED
    return {"redirect_uri": candidate, "prefix_match": prefix_ok,
            "exact_match": exact_ok, "code_theft_risk": prefix_ok and not exact_ok}

for c in sys.argv[1:]:
    print(classify(c))
```
