# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`llm-jailbreak-and-guardrails`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a versioned prompt set, a pinned model version, and the application's output filter in the loop.
- **Validation Gate:** a neutral/framed pair where the neutral request is refused and the outcome is recorded with the filter verdict.
- Pin temperature and seed where the provider allows; otherwise run each case several times and report the rate rather than a single result.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; c=json.load(open('guardrail-set.json'))['cases']; print(len(c))"` | Confirm the case set is versioned and countable | Cross-platform |
| `jq` | `jq ".results[].blocked" results.json` | List the blocked flag for each case so allowed cases can be counted | Linux, macOS |
| `curl` | `curl -sS $API/chat/completions -d @case.json` | Replay a single case against the pinned endpoint | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

results = json.load(open("results.json", encoding="utf-8"))["results"]
blocked = sum(1 for r in results if r["blocked"])
print("cases", len(results), "blocked", blocked, "allowed", len(results) - blocked)
print("model", results[0].get("model"), "filter", results[0].get("filter"))
```
