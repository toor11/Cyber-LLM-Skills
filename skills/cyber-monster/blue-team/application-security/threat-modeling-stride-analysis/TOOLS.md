# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-modeling-stride-analysis`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pytm` | `python -m pytm.threatmodel --dfd model.py` | Generate the element list from a declarative model so the grid cannot drift from the diagram | Cross-platform |
| `threagile` | `threagile -model model.yaml -output-dir out` | Rule-based risk output that can be diffed against the manual grid | Cross-platform |
| `rg` | `rg -n 'permitAll' src/` | Spot-check that a control location exists | Cross-platform |
| `git` | `git log -1 --format=%H -- threat-model/` | Bind the grid to a revision | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import csv, pathlib, sys

rows = list(csv.DictReader(open("stride.csv", encoding="utf-8")))
required = ["element", "category", "threat", "control_or_reason", "location"]
missing_cols = [c for c in required if c not in rows[0]]
if missing_cols:
    sys.exit(f"grid missing columns: {missing_cols}")

bad = []
for r in rows:
    has_threat = bool(r["threat"].strip())
    has_reason = r["control_or_reason"].strip().lower().startswith(("none", "n/a", "not applicable"))
    if not has_threat and not has_reason:
        bad.append((r["element"], r["category"], "no threat and no reason"))
    if has_threat and r["location"].strip() and not pathlib.Path(r["location"].split(":")[0]).exists():
        bad.append((r["element"], r["category"], f"location missing: {r['location']}"))

print("rows:", len(rows), "problems:", len(bad))
for b in bad[:20]:
    print(" ", b)
sys.exit(0 if not bad else 1)
```

## Verification

- The script exits zero only when every cell is a threat or a documented non-threat, which is the completeness property.
- A deliberately deleted location makes it fail, proving the control check is live.
- Rows and diagram element counts match, otherwise the grid is stale and should not be reviewed.
