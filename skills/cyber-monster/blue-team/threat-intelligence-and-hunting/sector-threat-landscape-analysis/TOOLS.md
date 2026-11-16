# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sector-threat-landscape-analysis`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `csv`/`pandas` | `pd.read_csv('isac-reports.csv').groupby('initial_access').size()` | Initial access distribution with counts | Cross-platform |
| `jq` | `jq 'group_by(.source_class)' reports.json` | Bias review by source class | Cross-platform |
| `libreoffice`/`sheets` | pivot table over the report extract | Year-over-year comparison under a consistent method | Cross-platform |
| `git` | `git log -- landscape/` | Method changes between periods | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import csv, collections

rows = list(csv.DictReader(open("isac-reports.csv")))
cohort = 1840
by_access = collections.Counter(r["initial_access"] for r in rows)
print("cohort:", cohort, "reports:", len(rows))
for access, n in by_access.most_common():
    print(f"  {access:28} n={n:3}  share_of_reports={n/len(rows):.0%}  of_cohort={n/cohort:.1%}")

# Exclude claims traced to a reporting-threshold change
excluded = [r for r in rows if r.get("threshold_changed") == "yes"]
print("excluded rows (threshold change):", len(excluded), "- not used for prevalence")
```

## Verification

- Both the share-of-reports and the share-of-cohort are printed, so the denominator is visible in the output.
- Excluded rows are counted separately rather than dropped, which keeps the artefact auditable.
- Re-running with a different cohort size changes the second percentage only, proving the denominator is what drives the claim.
