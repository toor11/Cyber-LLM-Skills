# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`smart-contract-audit-static-analysis-tooling`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Slither 0.11.x (detector set and printers), with the project's pinned compiler; an AST-based analyser for fast CI feedback.
- **Validation Gate:** `slither . --filter-paths 'test|script|lib'` exits 0 and produces a JSON document that parses.
- Slither requires a successful compilation; a build failure is a setup problem, not an absence of findings.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `slither` | `slither . --print human-summary` | Structural overview before detector triage | Cross-platform |
| `slither` | `slither . --json out.json --filter-paths test` | Machine-readable detector run scoped away from the test tree; repeat the path filter for the script and lib trees | Cross-platform |
| `forge` | `forge build --force` | Clean compile before analysis, avoiding stale artefacts | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

res = json.load(open("out.json", encoding="utf-8"))
dets = res.get("results", {}).get("detectors", [])
print(len(dets), "detector hits")
for d in dets[:15]:
    loc = d["elements"][0]["source_mapping"]["filename_relative"] if d.get("elements") else "?"
    print(d["check"], d["impact"], loc)
```
