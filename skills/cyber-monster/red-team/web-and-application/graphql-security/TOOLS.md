# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`graphql-security`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST https://target.example/graphql -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'` | Confirm the endpoint and capture a baseline response | Cross-platform |
| `graphw00f` | `graphw00f -d -t https://target.example/graphql` | Fingerprint the GraphQL engine to know which cost and introspection defaults apply | Linux, macOS, Windows |
| `InQL` | `Load the endpoint in the Burp extension to generate queries and mutations from the schema` | Map the full schema surface for targeted boundary probes | Cross-platform |

## Minimal Script Shape

A boundary-triage harness: it confirms the endpoint and whether introspection is enabled, then reminds the operator to test resolver and cost boundaries before claiming a crossing.

```python
import json, sys, urllib.request

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/graphql"

def gql(query):
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

introspection = gql("{ __schema { queryType { name } } }")
schema_exposed = "data" in introspection and introspection["data"].get("__schema") is not None
print({"endpoint": ENDPOINT, "introspection_enabled": schema_exposed,
       "note": "map resolvers and cost limits before claiming a boundary crossing"})
```
