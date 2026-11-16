# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`graphql-security-introspection-and-schema`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST https://target.example/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}'` | Send a direct introspection probe and capture the type list | Cross-platform |
| `clairvoyance` | `clairvoyance https://target.example/graphql -o schema.json` | Reconstruct the schema from field suggestions when introspection is disabled | Linux, macOS, Windows |
| `graphql-cop` | `graphql-cop -t https://target.example/graphql` | Audit introspection and error-verbosity configuration | Linux, macOS, Windows |

## Minimal Script Shape

A schema-recoverability harness: it tries direct introspection and, on refusal, sends a misspelled field to see whether error suggestions leak the schema indirectly.

```python
import json, sys, urllib.request

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/graphql"

def gql(query):
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

schema = gql("{ __schema { queryType { name } } }")
introspection_on = "__schema" in schema and "queryType" in schema
errors = gql("{ uzer { id } }")
suggests = "did you mean" in errors.lower()
print({"endpoint": ENDPOINT, "introspection_enabled": introspection_on,
       "error_field_suggestions": suggests,
       "schema_recoverable": introspection_on or suggests})
```
