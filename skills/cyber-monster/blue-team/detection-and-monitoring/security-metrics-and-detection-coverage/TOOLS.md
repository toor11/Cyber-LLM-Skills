# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`security-metrics-and-detection-coverage`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for computing, storing and publishing detection metrics. Never invent flags — check `--help` against the installed version, because DeTT&CT's argument letters and the Navigator schema version change between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| DeTT&CT (layer from detections) | `python dettect.py d -ft techniques-administration-endpoints.yaml -l` | Produce a Navigator layer from scored detections per technique, preserving `score_logbook` history | Cross-platform (Python 3) |
| DeTT&CT (layer from data sources) | `python dettect.py ds -fd data-sources-endpoints.yaml -l` | Produce a visibility-coverage layer before any detection scoring | Cross-platform (Python 3) |
| DeTT&CT (excel export) | `python dettect.py d -ft techniques-administration-endpoints.yaml -e` | Export the administration file for review where a layer is not the deliverable | Cross-platform (Python 3) |
| `jq` (layer diff) | `jq -r '.techniques[] .techniqueID' new.json` against `old.json` after `sort` | Show which techniques moved between two periods with identical scoring rules | Linux, macOS, Windows |
| `csvkit` | `csvstat --mean --median --count tickets.csv` | Quick distribution checks on ticket durations before writing a query | Cross-platform (Python 3) |
| `kubectl`/`curl` ticketing APIs | `curl -s -H "Authorization: Bearer $TOKEN" "$API/incidents?updated_since=$SINCE"` | Pull closed incidents with their state timestamps for MTTD/MTTR | Any host with API access |
| `sqlite3` | `sqlite3 metrics.db ".import tickets.csv tickets"` then SQL percentiles | Local, reproducible recomputation of a published number from stored inputs | Linux, macOS, Windows |

## Minimal Script Shape

The shape below is the minimum defensible metric run: it refuses to compute without a denominator and a framework version, then prints percentiles rather than a mean.

```python
#!/usr/bin/env python3
"""coverage_metrics.py — refuse to publish a ratio without its denominator."""
import json, sqlite3, sys

RELEVANT = "relevant_techniques.txt"   # one technique ID per line
ATTACK_VERSION = "v19"                 # pinned; v18 rows are not comparable
MIN_SAMPLE = 5                         # below this, report the cohort, not a percentile


def percentile(values, pct):
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((pct / 100) * (len(s) - 1)))))
    return s[k]


def main(db_path):
    relevant = {l.strip().upper() for l in open(RELEVANT) if l.strip()}
    con = sqlite3.connect(db_path)
    rows = con.execute(
        "select technique_id, tier from coverage where framework = ?", (ATTACK_VERSION,)
    ).fetchall()

    tiers = {}
    for tid, tier in rows:
        tid = (tid or "").upper()
        if tid in relevant:                      # denominator is the relevant set only
            tiers.setdefault(tier, set()).add(tid)

    out = {"framework": ATTACK_VERSION, "denominator": len(relevant)}
    for tier, ids in sorted(tiers.items()):
        out[tier] = {
            "techniques": len(ids),
            "pct_of_relevant": round(100.0 * len(ids) / max(1, len(relevant)), 1),
        }
    mttd = [r[0] for r in con.execute(
        "select mttd_minutes from incidents where first_evidence_utc is not null")]
    if len(mttd) >= MIN_SAMPLE:
        out["mttd"] = {"n": len(mttd), "p50": percentile(mttd, 50), "p95": percentile(mttd, 95)}
    else:
        out["mttd"] = {"n": len(mttd), "note": "cohort too small for percentiles"}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: coverage_metrics.py <metrics.db>")
    main(sys.argv[1])
```

## Notes That Prevent Wrong Runs

- A percentile over fewer than roughly five values is a restatement of the sample; report the raw cohort instead of a `p95`.
- DeTT&CT `score_logbook` entries are the only place history survives. Overwriting a `score` in place destroys the trend and makes last quarter's number unreproducible.
- Navigator layers should be regenerated from administration files, never hand-edited; a hand edit diverges from the scoring inputs and cannot be recomputed.
- Store the metric inputs (ticket rows, rule inventory snapshot, contract results) beside the output. A number whose inputs were discarded cannot be defended under review.
