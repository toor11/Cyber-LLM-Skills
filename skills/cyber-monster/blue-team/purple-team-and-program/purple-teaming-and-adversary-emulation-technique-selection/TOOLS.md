# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`purple-teaming-and-adversary-emulation-technique-selection`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `atomic-red-team` | `ls techniques/` in the cloned repository filtered to the technique id | Available emulations and their preconditions | Cross-platform |
| `sigma` | `sigma list rules/ --filter 'tags=T1218.011'` | Existing analytics for a technique | Cross-platform |
| `mitreattack-python` | `d.get_object_by_attack_id('T1685', 'attack-pattern')` | Confirm current technique ids after the v19 restructure | Cross-platform |
| `csv`/`sheets` | scoring sheet with relevance, coverage, safety columns | Auditable selection rationale | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import csv

SCORE = {"high": 3, "medium": 2, "low": 1}
rows = list(csv.DictReader(open("technique-candidates.csv")))
selected = []
for r in rows:
    relevance = SCORE[r["relevance"].lower()]
    gap = {"gap": 3, "partial": 2, "covered": 0}[r["coverage"].lower()]
    safe = {"safe": 2, "needs_isolation": 1, "tabletop": 0}[r["safety"].lower()]
    score = relevance * 2 + gap * 2 + safe
    branch = ("immediate" if relevance == 3 and gap >= 2 and safe == 2 else
              "regression" if gap == 0 else
              "tabletop" if safe == 0 else "defer")
    selected.append((score, r["technique"], branch))

for score, tech, branch in sorted(selected, reverse=True):
    print(f"{tech:14} score={score:2} branch={branch}")
```

## Verification

- A covered technique scores low regardless of relevance, which routes it to regression rather than the window.
- An unsafe technique lands in tabletop, proving the safety input can veto a high-relevance gap.
- Changing one relevance source to low moves the technique down the ordering, showing the score is live.
