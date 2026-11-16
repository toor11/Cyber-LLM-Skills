# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`openapi-and-graphql-schema-auditor-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** OpenAPI 3.2.x (current 3.2.1 adds no fields but clarifies encoding and path matching), `graphql-core` 3.x for schema building.
- **Validation Gate:** `openapi-spec-validator openapi.yaml` then the per-operation enumeration script.
- OpenAPI 3.2 added `query:` and `additionalOperations`, so enumerating only the classic methods undercounts operations.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `openapi-spec-validator` | `openapi-spec-validator openapi.yaml` | Reject an invalid document before auditing it | Cross-platform |
| `graphql-core` | `python -c "from graphql import build_client_schema; print('ok')"` | Build a typed schema from an introspection result | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' https://api.example/v1/orders` | Credentialed vs uncredentialed status differential | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import yaml

spec = yaml.safe_load(open("openapi.yaml"))
global_sec = spec.get("security", [])
METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace", "query"}
exposed = []
for path, item in spec.get("paths", {}).items():
    for method, op in item.items():
        if method not in METHODS:
            continue
        sec = op["security"] if "security" in op else global_sec
        if not sec:
            exposed.append((method.upper(), path, op.get("operationId")))
print(len(exposed), exposed[:5])
```
