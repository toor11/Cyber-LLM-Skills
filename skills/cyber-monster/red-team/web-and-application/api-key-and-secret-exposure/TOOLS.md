# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`api-key-and-secret-exposure`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `TruffleHog` | `trufflehog filesystem ./build --only-verified` | Surface only secrets that verify as live inside the built client assets, suppressing dead format matches | Cross-platform |
| `gitleaks` | `gitleaks detect --source . --redact` | Scan the full git history for committed secrets and print redacted locations rather than the raw value | Cross-platform |
| `curl` | `curl -s -o app.js https://target.example/assets/app.js` | Save the reachable bundle, then search app.js for an AWS key prefix before claiming exposure | Cross-platform |
| `Semgrep` | `semgrep --config p/secrets .` | Flag wholesale process.env injection and inlined keys at the build-config layer | Cross-platform |

## Minimal Script Shape

A client-surface sweep: it fetches each shipped asset and reports which provider secret prefixes are present, printing an exposure verdict rather than using any key it finds.

```python
import re
import sys
import urllib.request

PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "stripe_live": re.compile(r"sk_live_[0-9a-zA-Z]{10,}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "github_pat": re.compile(r"ghp_[0-9A-Za-z]{36}"),
}

def scan(url):
    body = urllib.request.urlopen(url, timeout=10).read().decode("utf-8", "replace")
    return {name: bool(rx.search(body)) for name, rx in PATTERNS.items()}

for target in sys.argv[1:]:
    found = scan(target)
    exposed = [name for name, hit in found.items() if hit]
    print({"asset": target, "exposed_prefixes": exposed,
           "verdict": "SECRET_EXPOSED" if exposed else "clean"})
```
