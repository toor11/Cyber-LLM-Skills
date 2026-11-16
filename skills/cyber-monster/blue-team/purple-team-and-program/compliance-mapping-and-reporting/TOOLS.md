# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`compliance-mapping-and-reporting`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `csv`/sheets | mapping sheet with framework, clause, control, test, evidence columns | Auditable crosswalk | Cross-platform |
| `jq` | `jq '.mappings' crosswalk.json` | Enumerate mappings for a filing extract | Cross-platform |
| `git` | `git log -p -- compliance/` | Show mapping changes against framework revisions | Cross-platform |
| `python` | script validating that every evidence path exists | Catch dangling evidence before a filing | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, os

cw = json.load(open("crosswalk.json"))
missing, multi_primary, unjustified = [], [], []
for m in cw["mappings"]:
    if m["status"] == "not_applicable":
        if not m.get("justification"):
            unjustified.append(m["clause"]["id"])
        continue
    pc = m.get("primary_control")
    if not pc:
        missing.append(m["clause"]["id"])
        continue
    if isinstance(pc, list) and len(pc) > 1:
        multi_primary.append(m["clause"]["id"])
    ev = m.get("evidence")
    if not ev or not os.path.exists(ev):
        missing.append(m["clause"]["id"])

print("mappings:", len(cw["mappings"]))
print("missing control or evidence:", missing)
print("clauses with multiple primary controls:", multi_primary)
print("unjustified exclusions:", unjustified)
```

## Verification

- A dangling evidence path is caught before the filing, which is the most common late failure.
- Multiple primary controls are flagged, so accountability stays single.
- An exclusion without justification fails, preventing silent omissions.
