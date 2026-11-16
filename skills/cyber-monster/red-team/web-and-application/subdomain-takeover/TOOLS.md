# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`subdomain-takeover`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +noall +answer CNAME assets-legacy.<target-domain> @1.1.1.1` | Follow the CNAME chain to its terminal target to classify the dangling category | Linux, macOS, Windows |
| `subjack` | `subjack -d <target-domain> -ssl -c fingerprints.json -v` | Match each subdomain response against known provider unclaimed-resource fingerprints | Linux, macOS, Windows |
| `nuclei` | `nuclei -t http/takeovers/ -u https://assets-legacy.<target-domain>` | Run the takeover template set to fingerprint the provider signature non-destructively | Cross-platform |
| `curl` | `curl -sS -i https://assets-legacy.<target-domain>/` | Capture the provider default or not-found body and headers that form the takeover fingerprint | Cross-platform |

## Minimal Script Shape

Resolves a candidate subdomain, fetches it when it resolves, and matches the body against a set of provider unclaimed-resource signatures to flag a likely dangling record.

```python
import socket
import urllib.request

NAME = "assets-legacy.target.example"
FINGERPRINTS = ["NoSuchBucket", "There isn't a GitHub Pages site here",
                "No such app", "Fastly error: unknown domain"]

def resolves(name):
    try:
        socket.gethostbyname(name)
        return True
    except socket.gaierror:
        return False

def body(name):
    try:
        with urllib.request.urlopen("https://" + name + "/", timeout=10) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as exc:
        return "ERR:" + exc.__class__.__name__

text = body(NAME) if resolves(NAME) else "NXDOMAIN"
hit = next((f for f in FINGERPRINTS if f in text), None)
print({"resolves": resolves(NAME), "fingerprint": hit,
       "likely_dangling": hit is not None})
```
