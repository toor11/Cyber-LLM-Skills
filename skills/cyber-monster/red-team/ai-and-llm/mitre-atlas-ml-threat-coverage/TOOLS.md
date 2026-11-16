# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`mitre-atlas-ml-threat-coverage`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a coverage matrix keyed by component and technique id, with observable, control, and a separate gap list.
- **Validation Gate:** one technique traced from matrix row to a telemetry query that returns events.
- ATLAS technique ids change as the matrix evolves; record the matrix version with the mapping.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(len(yaml.safe_load(open('atlas-map.yaml'))['rows']))"` | Count mapped techniques | Cross-platform |
| `jq` | `jq ".gaps" atlas-map.json` | List declared gaps so they can be counted | Linux, macOS |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' $ATLAS_URL` | Confirm the matrix reference is reachable | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import yaml

m = yaml.safe_load(open("atlas-map.yaml", encoding="utf-8"))
rows = m["rows"]
untested = [r for r in rows if not r.get("observable") or not r.get("control")]
print("rows", len(rows), "untested", len(untested), "gaps", len(m.get("gaps", [])))
```
