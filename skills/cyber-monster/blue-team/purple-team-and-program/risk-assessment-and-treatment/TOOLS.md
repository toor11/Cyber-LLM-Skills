# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`risk-assessment-and-treatment`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `csv`/sheets | risk register with scenario, likelihood, impact, residual, treatment columns | Comparable, sortable register | Cross-platform |
| `python` | score computation from anchors and control factors | Consistency across assessors | Cross-platform |
| `jq` | `jq '.risks' register.json` | Enumerate entries for review | Cross-platform |
| `git` | `git log -p -- risk/register.yml` | Show how a score changed and why | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, datetime as dt

reg = json.load(open("risk-register.json"))
today = dt.date(2026, 11, 14)
problems = []
for r in reg["risks"]:
    if r["treatment"] not in {"mitigate", "transfer", "avoid", "accept"}:
        problems.append((r["id"], "invalid treatment"))
    if r["treatment"] == "accept" and not r.get("review"):
        problems.append((r["id"], "accepted without expiry"))
    if r.get("review") and dt.date.fromisoformat(r["review"]) < today:
        problems.append((r["id"], "review overdue"))
    if not r.get("controls_considered"):
        problems.append((r["id"], "residual score without named controls"))
    if r["residual"] >= 12 and r["treatment"] == "accept":
        problems.append((r["id"], "high residual accepted - needs explicit authority"))

print("risks:", len(reg["risks"]), "problems:", len(problems))
for p in problems[:10]:
    print(" ", p)
```

## Verification

- An accepted risk above the tolerance threshold is flagged, which forces an explicit authority decision.
- A residual score without named controls fails, because the score would be uninterpretable.
- Overdue reviews appear in the same output, so the register stays live.
