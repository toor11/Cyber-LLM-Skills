# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`enterprise-appliance-n-day-mail-collaboration`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sI https://mail.example/owa/` | Fingerprint the platform and read version headers | Cross-platform |
| `nuclei` | `nuclei -u https://mail.example -tags cve,exchange -nc` | Run mail and collaboration CVE detection templates as benign oracles | Linux, Windows, macOS |
| `httpx` | `httpx -u https://mail.example -path /autodiscover/autodiscover.xml -sc -title` | Probe routing endpoints and capture status and titles | Linux, Windows, macOS |
| `Shodan CLI` | `shodan host <ip>` | Corroborate internet exposure of the webmail or management surface | Cross-platform |

## Minimal Script Shape

A mail/collaboration gate: it compares the platform build to a fixed-version map and factors in surface exposure and backend reachability to print a non-exploitation verdict.

```python
from packaging import version

FIXED = {"GoAnywhere MFT": "7.8.4"}

def mail_verdict(product, build, surface_exposed, backend_reachable):
    fixed = FIXED.get(product)
    if fixed is None:
        return "no advisory mapping"
    try:
        affected = version.parse(build) < version.parse(fixed)
    except Exception:
        return "fingerprint build exactly"
    if not affected:
        return "patched / non-finding"
    if not surface_exposed or not backend_reachable:
        return "affected build but vulnerable surface restricted"
    return "affected and reachable: benign probe only"

print({"product": "GoAnywhere MFT", "build": "7.7.0",
       "verdict": mail_verdict("GoAnywhere MFT", "7.7.0", True, True)})
```
