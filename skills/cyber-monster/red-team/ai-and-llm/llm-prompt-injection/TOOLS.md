# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`llm-prompt-injection`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a replay harness with a fixed temperature and seed where the provider allows it, capturing raw output and tool calls.
- **Validation Gate:** one benign run and one injected run, both archived, with the differential stated explicitly.
- Record the model version and system prompt verbatim; a finding that cannot be reproduced against the same version is not reviewable.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print(len(json.load(open('probe.json'))['tool_calls']))"` | Count tool calls in a captured run | Cross-platform |
| `jq` | `jq '.tool_calls' probe.json` | Inspect the tool-call list from a capture | Linux, macOS |
| `curl` | `curl -sS $API/chat/completions -H 'content-type: application/json' -d @payload.json` | Replay the exact request against the endpoint | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

base = json.load(open("baseline.json", encoding="utf-8"))
probe = json.load(open("probe.json", encoding="utf-8"))
print("baseline tools", base.get("tool_calls"))
print("probe tools", probe.get("tool_calls"))
print("differential", bool(probe.get("tool_calls")) and not base.get("tool_calls"))
```
