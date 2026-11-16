# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-intelligence-and-cti-strategic-intelligence`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `git` | `git log -- products/strategic/` | Show which products fed a decision and when | Cross-platform |
| `jq` | `jq '.assumptions' planning.json` | Diff the current planning assumption against the product's delta | Cross-platform |
| `markdown`/`pandoc` | `pandoc product.md -o product.pdf --template brief.tex` | Consistent brief format for a decision forum | Cross-platform |
| `spreadsheet`/`csv` | exposure counts by appliance and MFA state | Internal evidence for the delta | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, datetime as dt

plan = json.load(open("planning-assumptions.json"))
prod = json.load(open("products/strategic-fy27.json"))

for a in plan["assumptions"]:
    delta = next((d for d in prod["deltas"] if d["assumption_id"] == a["id"]), None)
    status = "unchanged" if delta is None else delta["effect"]
    print(f'{a["id"]:12} {a["statement"][:60]:62} -> {status}')

horizon = dt.date.fromisoformat(prod["horizon_end"])
print("horizon remaining days:", (horizon - dt.date(2026, 11, 14)).days)
print("confidence:", prod["confidence"], "basis:", prod["confidence_basis"][:80])
```

## Verification

- Every planning assumption is either addressed by a delta or explicitly marked unchanged, so gaps in the product are visible.
- The confidence basis prints alongside the level, so a reader can judge it.
- A product with no delta rows produces all `unchanged`, which correctly signals no decision input.
