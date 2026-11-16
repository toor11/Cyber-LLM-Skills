# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ai-guardrail-and-classifier-bypass`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a paired case set with expected verdicts, and the classifier's label and score recorded per case.
- **Validation Gate:** one encoding class where the blocked and bypass forms receive different verdicts.
- Record the classifier version and threshold; a bypass against a different build is not reproducible.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; c=json.load(open('guardrail-cases.json'))['cases']; print(len(c))"` | Confirm the case set size | Cross-platform |
| `jq` | `jq ".cases[].verdict" verdicts.json` | List classifier verdicts so they can be compared with the expected label | Linux, macOS |
| `curl` | `curl -sS -X POST $API/chat -d @case.json` | Submit one case to the guarded endpoint | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

rows = json.load(open("verdicts.json", encoding="utf-8"))["cases"]
bypass = [r["id"] for r in rows if r["expect"] == "blocked" and r["verdict"] != "blocked"]
print("cases", len(rows), "bypasses", bypass)
```
