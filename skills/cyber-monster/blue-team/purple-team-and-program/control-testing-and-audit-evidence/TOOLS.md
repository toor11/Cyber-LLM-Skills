# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`control-testing-and-audit-evidence`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `siem`/SIEM extract | query producing the full population with timestamps | Population definition and completeness | Cross-platform |
| `python random` | `random.Random(20261102).sample(population, 12)` | Reproducible sample selection with a recorded seed | Cross-platform |
| `git`/document store | evidence committed under a control-and-period path | Evidence traceability | Cross-platform |
| `csv` | workpaper with instance, disposition, evidence columns | Auditable test record | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import csv, random

population = [r["instance"] for r in csv.DictReader(open("access-review-population.csv"))]
seed = 20261102
sample = random.Random(seed).sample(population, k=min(12, len(population)))
print("population:", len(population), "seed:", seed, "sample:", len(sample))

rows = list(csv.DictReader(open("access-review-workpaper.csv")))
tested = {r["instance"] for r in rows}
print("sampled but untested:", sorted(set(sample) - tested))
exceptions = [r for r in rows if r["disposition"] != "pass"]
print("exceptions:", [(r["instance"], r["disposition"]) for r in exceptions])
print("operating conclusion:", "effective" if not exceptions else
      f"partial ({len(exceptions)} of {len(rows)} samples)")
```

## Verification

- The sample is reproducible from the recorded seed, which is the audit requirement.
- Sampled-but-untested instances are printed, so an incomplete workpaper cannot be reported as complete.
- Exceptions change the conclusion to partial, proving the result is computed rather than asserted.
