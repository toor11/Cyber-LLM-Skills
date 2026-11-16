# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ml-adversarial-and-data-poisoning`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a fixed evaluation set, paired clean and perturbed inputs, and a training-data provenance record.
- **Validation Gate:** a shift rate computed over the whole evaluation set rather than a single example.
- Record the model version and the evaluation-set hash with every result; a shift rate without both is not comparable.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print(len(json.load(open('eval-set.json'))['cases']))"` | Confirm the evaluation set size | Cross-platform |
| `jq` | `jq ".results[].perturbed" results.json` | List perturbed labels so flips against the clean label can be counted | Linux, macOS |
| `curl` | `curl -sS -X POST $API/predict -d @case.json` | Query the endpoint once per case with a recorded payload | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

results = json.load(open("results.json", encoding="utf-8"))["results"]
flips = [r for r in results if r["clean"] != r["perturbed"]]
print("cases", len(results), "flips", len(flips))
print("median margin", sorted(r["margin"] for r in results)[len(results) // 2])
```
