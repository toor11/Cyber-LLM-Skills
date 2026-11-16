# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`rag-and-vector-store-attacks`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a vector store whose search accepts a metadata filter, and an ingestion pipeline recording source and owner per chunk.
- **Validation Gate:** one query whose filter is printed and whose returned chunk tenants are all asserted equal to the caller's.
- Filter support varies by store; some apply filters after the ANN search, which reintroduces the slot-consumption problem.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print(json.load(open('query.json'))['filter'])"` | Confirm the filter is part of the query, not a post-step | Cross-platform |
| `curl` | `curl -sS -X POST $API/search -d @query.json` | Replay a retrieval with an explicit filter | Cross-platform |
| `jq` | `jq ".hits[].tenant" hits.json` | List tenant ids present in a result set | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

hits = json.load(open("hits.json", encoding="utf-8"))["hits"]
tenants = sorted({h["tenant"] for h in hits})
print("hits", len(hits), "tenants", tenants)
print("cross-tenant" if len(tenants) > 1 else "single-tenant")
```
