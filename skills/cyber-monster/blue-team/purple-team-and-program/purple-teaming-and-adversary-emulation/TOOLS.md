# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`purple-teaming-and-adversary-emulation`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `atomic-operator` | `atomic-operator run -t techniques/T1218.011 -r hosts.txt --input-arguments cleanup=true` | Scripted emulation with cleanup | Cross-platform |
| `invoke-atomicredteam` | `Invoke-AtomicTest T1218.011 -TestNumbers 1 -GetPrereqs` | Check preconditions before emulating | Windows |
| `siem` | query the predicted observable with a time bound around the window | Probe evidence and alert latency | Cross-platform |
| `jq` | `jq 'select(.technique=="T1053.005")' outcomes.json` | Outcome rollup per technique | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, datetime as dt

rows = [json.loads(l) for l in open("outcomes.jsonl")]
VALID = {"detected", "logged_not_detected", "absent"}

problems = []
for r in rows:
    if r["outcome"] not in VALID:
        problems.append((r["technique"], "invalid outcome class"))
    if not r.get("prediction_date"):
        problems.append((r["technique"], "no prediction recorded before the window"))
    elif r["prediction_date"] >= r["window_start"]:
        problems.append((r["technique"], "prediction recorded after the window opened"))
    if not r.get("evidence"):
        problems.append((r["technique"], "no probe evidence reference"))
    if r["outcome"] != "detected" and not r.get("ticket"):
        problems.append((r["technique"], "gap with no ticket"))

print("techniques:", len(rows), "problems:", len(problems))
for p in problems[:10]:
    print(" ", p)
raise SystemExit(0 if not problems else 1)
```

## Verification

- A prediction dated after the window start fails the check, which prevents retro-fitted predictions.
- Every non-detected outcome requires a ticket, so gaps cannot be dropped.
- Re-running after adding a re-run record shows the technique as closed rather than open.
