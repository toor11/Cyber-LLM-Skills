# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `wafw00f` | `wafw00f https://target.example -a` | Fingerprint the WAF vendor from block pages and headers so the correct rule-gap set is selected | Linux, Windows, macOS |
| `curl` | `curl -sS -i 'https://target.example/?wafprobe-fp=1'` | Capture the vendor block-page signature and status so later origin responses are distinguishable | Cross-platform |
| `nuclei` | `nuclei -u https://target.example -tags waf -rl 5` | Run WAF-identification templates at a capped request rate to avoid triggering a ban during fingerprinting | Cross-platform |
| `ffuf` | `ffuf -w forms.txt:FORM -u 'https://target.example/?x=FORM' -rate 5 -mc all -ac` | Compare canonical and engine-specific variants at a safe rate and auto-calibrate out challenge pages | Linux, Windows, macOS |

## Minimal Script Shape

A paced fingerprint-and-gap harness: it reads the block signature on a canonical trigger and checks whether an engine-specific variant reaches the origin, spacing requests to avoid a rate ban.

```python
import time
import urllib.request
import urllib.error

BASE = 'https://target.example/'

def get(qs):
    req = urllib.request.Request(BASE + '?' + qs,
                                 headers={'User-Agent': 'wafprobe-fingerprint/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get('Server', ''), len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get('Server', ''), 0

canonical = get('x=wafprobe-canary-generic')
time.sleep(1.0)                      # rate-safe spacing
variant = get('x=wafprobe-canary-variant')
blocked = canonical[0] in (403, 406)
reached = variant[0] not in (403, 406, 429)
print({'canonical': canonical, 'variant': variant,
       'rule_gap': blocked and reached})
```
