# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`soc-operations-and-shift-process`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `siem`/ticketing export | queue export with created, first-touched, closed, reason fields | Time in queue and closure distribution | Cross-platform |
| `python` | median and p90 over queue timestamps | Robust queue metrics | Cross-platform |
| `jq` | `jq 'group_by(.closure_reason)' closures.json` | Closure-mix analysis | Cross-platform |
| `git` | `git log -p -- runbook/` | Show that entry criteria changed and when | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, statistics, collections

rows = [json.loads(l) for l in open("queue-export.jsonl")]
closed = [r for r in rows if r.get("closed_at")]
wait = [(r["closed_at"] - r["created_at"]) / 60 for r in closed]
wait.sort()
print("closed:", len(closed), "median minutes:", round(statistics.median(wait), 1) if wait else None,
      "p90:", round(wait[int(len(wait) * 0.9)], 1) if wait else None)

mix = collections.Counter(r["closure_reason"] for r in closed)
for reason, n in mix.most_common():
    print(f"  {reason:20} {n:5} {n/len(closed):.0%}")

missing = [r["id"] for r in closed if not r.get("closure_reason")]
print("closures without a reason:", len(missing))
bad = [r["id"] for r in closed if r["closure_reason"] == "true_positive" and not r.get("evidence")]
print("true positives without evidence:", len(bad))
```

## Verification

- Closures missing a reason are counted, which is the decision-record completeness check.
- True positives without evidence are flagged, which is the audit-critical class.
- The closure mix shows whether insufficient-data closures dominate, which points at tuning rather than analyst effort.
