# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ai-application-assessment`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a surface map (prompt, output, tools, data) with a control and a probe per surface.
- **Validation Gate:** one probe per surface showing the control acting, or an accepted risk with its impact named.
- Record the model version and system prompt with the assessment; a surface map without them cannot be reproduced.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(sorted(yaml.safe_load(open('surface-map.yaml'))['surfaces']))"` | Confirm all four surfaces are covered | Cross-platform |
| `jq` | `jq ".surfaces" surface-map.json` | List assessed surfaces when the map is JSON | Linux, macOS |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -X POST $API/chat -d @probe.json` | Replay a surface probe against the endpoint | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import yaml

m = yaml.safe_load(open("surface-map.yaml", encoding="utf-8"))["surfaces"]
for name, spec in m.items():
    status = "controlled" if spec.get("probe_result") == "blocked" else "gap"
    print(name, status, spec.get("control"))
```
