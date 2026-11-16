# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`bug-bounty-target-prioritization`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a programme record with policy extract, scope, exclusions, severity table, retrieval date, and per-surface change signal.
- **Validation Gate:** one surface traced from policy scope to payout band to change signal before research begins.
- Policy pages change without notice; record the retrieval date and re-read before submitting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o openapi.json https://api.client.example/v3/openapi.json` | Save a recently added spec, then count keys under paths to measure the surface | Cross-platform |
| `python` | `python -c "import yaml; print(yaml.safe_load(open('programme.yaml'))['severity'])"` | Read the payout table before choosing a target | Cross-platform |
| `jq` | `jq ".paths" spec.json` | List endpoints on a candidate surface | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import yaml

prog = yaml.safe_load(open("programme.yaml", encoding="utf-8"))
spec = json.load(open("v3-openapi.json", encoding="utf-8"))
paths = list(spec.get("paths", {}))
print("policy retrieved", prog["retrieved_at"])
print("scoped", prog["scope"], "exclusions", prog.get("exclusions"))
print("fresh endpoints", len(paths), paths[:5])
```
