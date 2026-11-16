# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`security-awareness-and-training-program`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mail gateway` | query reports submitted via the report button with timestamps | Time-to-report distribution | Cross-platform |
| `python` | median and percentiles over report timestamps | Robust central tendency for skewed reporting data | Cross-platform |
| `helpdesk` | ticket count by category for payment verification | Process behaviour metric | Cross-platform |
| `idp` | active users of the password manager integration | Adoption metric from the identity provider rather than the training platform | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import statistics, json

reports = [json.loads(l) for l in open("phish-reports.jsonl")]
deltas = [(r["reported_at"] - r["delivered_at"]) / 60 for r in reports if r.get("delivered_at")]
if deltas:
    deltas.sort()
    print("n:", len(deltas))
    print("median minutes:", round(statistics.median(deltas), 1))
    print("p90 minutes:", round(deltas[int(len(deltas) * 0.9)], 1))
    print("within 30 min:", f"{sum(d <= 30 for d in deltas) / len(deltas):.0%}")

vol = json.load(open("report-volume.json"))
for period, count in vol.items():
    print(period, "reports per 1000 users:", round(count["reports"] / count["users"] * 1000, 1))
```

## Verification

- Median and p90 are both reported, because a fast median with a slow tail still leaves exposure.
- The share within the target window is computed, which is the behaviour the programme targets.
- Volume is normalised per 1,000 users, so population changes do not create false trends.
