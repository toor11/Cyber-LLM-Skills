# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`post-incident-review-and-lessons`](SKILL.md) | Family: **Incident Response**

Verified review tooling. Everything here reconstructs, compares or tracks; none of it modifies evidence, and none replaces the decision record.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `log2timeline.py` / `psort.py` | `psort.py -o l2tcsv -w pir-window.csv case.plaso --slice <t> --slice_size 60` | Extract the review window from an existing Plaso store without re-parsing | Cross-platform |
| `Timesketch` (`tsctl`) | `tsctl import --name IR-2026-0417 timeline.csv` | Collaborative timeline annotation where confirmed and inferred are tagged as attributes | Linux (server) |
| `git log` | `git log --since=<t0> --until=<t3> --format="%aI %an %s" -- config/` | Configuration change history across the incident window with authorship and time | Cross-platform |
| `jq` | `jq -r 'map(select(.verify_result == null))' actions.json` | List actions with no verification result before the closure review | Cross-platform |
| `pandoc` | `pandoc pir.md -o pir.pdf --toc --number-sections` | Render the review record from a reviewable, diffable source | Cross-platform |
| `sqlite3` | `sqlite3 metrics.db "select case_id, dwell_h from intervals order by case_id"` | Trend extraction across incidents measured the same way | Cross-platform |

## Minimal Script Shape

The shape below produces the two things a review cannot proceed without: a confirmed-only interval set, and an action register that refuses closure without a verification result. It writes only to a case directory.

```bash
#!/usr/bin/env bash
# pir-gate.sh — interval measurement and action-closure gate. Read-only against evidence.
set -euo pipefail

CASE="${CASE:?case directory}"
OUT="$CASE/pir"
mkdir -p "$OUT"

# Gate 1: intervals must come from the timeline file, not from recollection.
if [ ! -f "$CASE/timeline.tsv" ]; then
  echo "BLOCKED: no timeline.tsv. Reconstruct before reviewing causes."; exit 2
fi

python3 - "$CASE/timeline.tsv" "$OUT/intervals.tsv" <<'PY'
import sys, csv
src, out = sys.argv[1], sys.argv[2]
need = {"first_execution","first_detection","acknowledged","containment_effective","recovered"}
rows, unconfirmed = {}, []
with open(src) as f:
    for r in csv.DictReader(f, delimiter="\t"):
        if r.get("confidence") != "confirmed":
            unconfirmed.append(r.get("marker")); continue
        rows.setdefault(r["marker"], r["utc"])
missing = need - set(rows)
if missing:
    print("GAP: no confirmed timestamp for:", ", ".join(sorted(missing)))
with open(out, "w", newline="") as f:
    w = csv.writer(f, delimiter="\t"); w.writerow(["interval","value"])
    try:
        order = ["first_execution","first_detection","acknowledged","containment_effective","recovered"]
        for a, b in zip(order, order[1:]):
            if a in rows and b in rows:
                print(f"{a}->{b}  {rows[a]} .. {rows[b]}")
    except Exception:
        pass
print("excluded as unconfirmed:", ", ".join(unconfirmed) or "none")
PY

# Gate 2: no action closes without a verification result recorded after deployment.
if [ -f "$OUT/actions.tsv" ]; then
  awk -F'\t' 'NR==1 || ($5=="closed" && $7=="") {
      print (NR==1 ? "id\towner\tdue\tstate\tverify_test\tdeployed\tverify_result" : $0)
  }' "$OUT/actions.tsv" > "$OUT/actions-needing-evidence.tsv"
  if [ "$(wc -l < "$OUT/actions-needing-evidence.tsv")" -gt 1 ]; then
    echo "REVIEW: actions closed without a verification result:"
    cat "$OUT/actions-needing-evidence.tsv"
  fi
fi

echo "next: test each contributing factor against a comparable case before naming a cause"
```

## Notes That Prevent Wrong Runs

- Measure intervals only from confirmed timestamps. A review that mixes inferred and confirmed values produces a trend that moves for reasons unrelated to capability, and the movement will be attributed to the last change made.
- A verification test run before the fix was deployed proves nothing. Compare the verification timestamp against the deployment timestamp every time.
- Where a long lookback exceeds Defender XDR's 30-day retention, the data may exist only in the Microsoft Sentinel data lake — invisible to workspace queries, analytics rules and the Logs blade. Query the lake endpoint and record which plane answered.
- Keep the review record in version control. Diffable review documents make it obvious when a finding or action was quietly softened between draft and publication.
- `pandoc` output is a rendering. The source markdown is the record; circulate both, or the rendering becomes the only version anyone can find.

## Review Cadence

- Publish urgent lessons during the incident, not after recovery; NIST SP 800-61r3 treats improvement as continuous and maps it to CSF 2.0 ID.IM-01 through ID.IM-04.
- Hold the formal review within a few business days of recovery, before recollections diverge from the log.
- Review open actions monthly with leadership visibility, and escalate overdue items by rule rather than by memory.
