# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`llm-denial-of-service-and-cost`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** server-enforced `max_tokens`, context truncation, a per-user token quota, and an explicit iteration counter.
- **Validation Gate:** one worst-case request that the quota rejects, and one loop that terminates at the counter.
- Token accounting varies by provider; record the accounting field used so the cost comparison is reproducible.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print(json.load(open('usage.json'))['total_tokens'])"` | Read token accounting from a captured response | Cross-platform |
| `jq` | `jq '.usage' response.json` | Inspect the usage block of a model response | Linux, macOS |
| `curl` | `curl -sS -X POST $API/chat -d @max-request.json` | Replay the worst-case request for cost measurement | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

med = json.load(open("usage-median.json", encoding="utf-8"))["total_tokens"]
worst = json.load(open("usage-max.json", encoding="utf-8"))["total_tokens"]
print("median", med, "worst", worst, "amplification", round(worst / max(med, 1), 1))
```
