# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`subdomain-takeover-cname-fingerprints`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dnsx` | `dnsx -l subs.txt -cname -resp-only` | Bulk-resolve subdomains to their terminal CNAME targets for fingerprint classification | Linux, macOS, Windows |
| `subjack` | `subjack -w subs.txt -ssl -c fingerprints.json -o hits.txt` | Match each CNAME response against the provider fingerprint database | Linux, macOS, Windows |
| `nuclei` | `nuclei -t http/takeovers/ -l subs.txt` | Apply the maintained takeover signatures to each candidate CNAME | Cross-platform |
| `curl` | `curl -sS -i https://marketing.<target-domain>/` | Capture the provider body for manual signature confirmation | Cross-platform |

## Minimal Script Shape

Fetches a candidate CNAME over HTTPS and compares the body against a provider-signature map, reporting the matched provider when a dangling CNAME is likely.

```python
import ssl
import urllib.request

CANDIDATE = "marketing.target.example"
SIGNATURES = {
    "github-pages": "there isn't a github pages site here",
    "aws-s3": "nosuchbucket",
    "heroku": "no such app",
    "fastly": "fastly error: unknown domain",
}

def fetch(host):
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen("https://" + host + "/", timeout=10, context=ctx) as r:
            return r.read().decode("utf-8", "replace").lower()
    except Exception as exc:
        return "err:" + exc.__class__.__name__

body = fetch(CANDIDATE)
match = next((p for p, sig in SIGNATURES.items() if sig in body), None)
print({"candidate": CANDIDATE, "provider_fingerprint": match,
       "dangling_cname_suspected": match is not None})
```
