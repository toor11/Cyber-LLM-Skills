# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`security-program-and-control-frameworks`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| NIST CSF 2.0 profile template | download the spreadsheet and record current and target states | Organisational Profile with gap analysis | Cross-platform |
| `csv`/`sheets` | control register with satisfies, owner, test columns | Auditable mapping table | Cross-platform |
| `jq` | `jq '.controls' register.json` | Find controls never tested | Cross-platform |
| CIS Controls v8.1 | safeguard list with IG assignments | Requirement source for the mapping | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, datetime as dt

reg = json.load(open("control-register.json"))
today = dt.date(2026, 11, 14)
problems = []
for c in reg["controls"]:
    if not c.get("owner"):
        problems.append((c["id"], "no owner"))
    if not c.get("test", {}).get("method"):
        problems.append((c["id"], "no test method"))
    last = c.get("test", {}).get("last")
    if not last:
        problems.append((c["id"], "never tested"))
    elif (today - dt.date.fromisoformat(last)).days > 120:
        problems.append((c["id"], f"last test {last} older than one quarter"))
    if not c.get("satisfies"):
        problems.append((c["id"], "no framework or risk justification"))

print("controls:", len(reg["controls"]), "problems:", len(problems))
for p in problems[:10]:
    print(" ", p)
print("frameworks:", reg.get("framework_versions"))
```

## Verification

- Controls without a test method are flagged, which is the implemented-versus-tested distinction.
- Stale test dates appear, so the profile cannot claim currency it does not have.
- Framework versions print alongside, so a stale mapping is visible in the same view.
