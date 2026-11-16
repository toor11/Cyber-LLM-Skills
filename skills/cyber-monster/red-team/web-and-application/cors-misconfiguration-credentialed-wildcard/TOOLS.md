# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cors-misconfiguration-credentialed-wildcard`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/api/profile' -H 'Origin: https://wildcard-probe.target.example'` | Check whether an arbitrary sibling subdomain is echoed with credentials true | Cross-platform |
| `Corsy` | `python corsy.py -u https://target.example/api/profile` | Test wildcard-with-credentials and subdomain-trust conditions automatically | Cross-platform |
| `dig` | `dig +short CNAME portal.target.example` | Check whether a trusted subdomain is a dangling CNAME eligible for takeover | Linux, macOS, Windows |

## Minimal Script Shape

A subdomain-trust harness: it sends an arbitrary sibling subdomain and a legitimate one, then reports whether the server trusts the whole domain tree with credentials.

```python
import urllib.request

ENDPOINT = "https://target.example/api/profile"

def headers_for(origin):
    req = urllib.request.Request(ENDPOINT, headers={"Origin": origin})
    with urllib.request.urlopen(req, timeout=10) as r:
        return (r.headers.get("Access-Control-Allow-Origin"),
                (r.headers.get("Access-Control-Allow-Credentials") or "").lower())

arbitrary = "https://wildcard-probe.target.example"
acao, acac = headers_for(arbitrary)
# A reflected arbitrary subdomain plus credentials true widens trust to any sibling host
print({"allow_origin": acao, "allow_credentials": acac,
       "subdomain_tree_trusted": acao == arbitrary and acac == "true"})
```
