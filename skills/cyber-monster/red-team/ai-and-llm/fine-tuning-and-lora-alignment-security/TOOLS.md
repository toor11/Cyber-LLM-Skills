# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`fine-tuning-and-lora-alignment-security`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a versioned safety evaluation set, adapter and dataset hashes, and a canary string inserted into training data.
- **Validation Gate:** the same evaluation set run against base and trained artefacts, with the changed cases listed.
- Record the base model version alongside the adapter hash; an adapter evaluated against a different base is not comparable.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print(len(json.load(open('safety-eval.json'))['cases']))"` | Confirm the evaluation set is versioned | Cross-platform |
| `sha256sum` | `sha256sum style-lora.safetensors` | Verify the adapter artefact hash | Linux, macOS |
| `jq` | `jq ".cases[].refused" eval-tuned.json` | List refusal flags so non-refusals in a trained-model run can be counted | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

base = json.load(open("eval-base.json", encoding="utf-8"))
tuned = json.load(open("eval-tuned.json", encoding="utf-8"))
regressions = [k for k in base if base[k].get("refused") and not tuned.get(k, {}).get("refused")]
print("cases", len(base), "regressions", regressions[:10])
```
