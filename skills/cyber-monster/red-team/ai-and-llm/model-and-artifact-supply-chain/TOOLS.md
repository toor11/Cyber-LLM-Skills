# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`model-and-artifact-supply-chain`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `safetensors.torch.load_file` for data-only loading, SHA-256 verification against a manifest, and signed artefact attestations where available.
- **Validation Gate:** a hash comparison that fails closed on mismatch, exercised with a modified copy.
- `torch.load` with `weights_only=True` narrows the pickle surface but does not eliminate it; prefer a data-only format.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sha256sum` | `sha256sum model.safetensors` | Record and compare artefact hashes | Linux, macOS |
| `safetensors` | `python -c "from safetensors.torch import load_file; print('ok')"` | Confirm the data-only loader is available | Cross-platform |
| `python` | `python -c "import json; print(json.load(open('manifest.json')))"` | Read the provenance manifest the gate compares against | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import json

EXPECTED = json.load(open("manifest.json", encoding="utf-8"))["weights_sha256"]
actual = hashlib.sha256(open("model.safetensors", "rb").read()).hexdigest()
print("match" if actual == EXPECTED else "MISMATCH", actual[:16])
```
