# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`llm-data-exfiltration-and-leakage`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** retrieval with a tenant filter in the query, chunk ids in the answer metadata, and an allowlist for outbound references.
- **Validation Gate:** two accounts returning disjoint chunk id sets for the same query.
- Test with accounts that have overlapping but non-identical permissions; identical test accounts hide group-based ACL gaps.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print(json.load(open('answer-a.json'))['chunk_ids'])"` | Inspect the retrieved set behind an answer | Cross-platform |
| `jq` | `jq '.chunk_ids' answer-b.json` | Compare chunk ids across accounts | Linux, macOS |
| `curl` | `curl -sS -X POST $API/chat -H "authorization: Bearer $TOKEN_B" -d @query.json` | Replay the same query as a second account | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

a = set(json.load(open("answer-a.json", encoding="utf-8"))["chunk_ids"])
b = set(json.load(open("answer-b.json", encoding="utf-8"))["chunk_ids"])
print("shared chunks", len(a & b))
print("leak" if a & b else "disjoint")
```
