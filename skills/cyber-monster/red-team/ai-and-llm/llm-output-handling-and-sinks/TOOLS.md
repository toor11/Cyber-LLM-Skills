# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`llm-output-handling-and-sinks`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** sink-specific encoding (`html.escape`, a maintained markdown sanitiser), parameter binding for queries, and argument arrays for subprocess calls.
- **Validation Gate:** one probe per sink showing the metacharacter is inert, with the transformed text recorded.
- A model-side instruction to avoid HTML is not a control and should never be recorded as one in the assessment.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import html; print(html.escape('<script>x</script>'))"` | Confirm the escaping function used at the render sink | Cross-platform |
| `jq` | `jq ".sinks" sinks.json` | List the sinks the assessment must cover | Linux, macOS |
| `curl` | `curl -sS -X POST $API/chat -d @probe.json` | Produce model output containing the sink metacharacter | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import html

raw = '<script>alert(1)</script>'
print("raw      ", raw)
print("escaped  ", html.escape(raw))
print("inert    ", "&lt;script&gt;" in html.escape(raw))
```
