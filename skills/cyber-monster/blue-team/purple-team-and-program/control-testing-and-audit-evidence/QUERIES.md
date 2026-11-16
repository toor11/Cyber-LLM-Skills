# Detection Queries and Telemetry Artifacts

> Sub-skill: [`control-testing-and-audit-evidence`](SKILL.md) | Family: **Purple Team and Program**

Test-workpaper checks. Each row names the field and the state a defensible test shows.

## Population

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Definition | population statement with count and period | Present |
| Completeness | how completeness was verified (system extract, reconciliation) | Recorded |
| Split handling | populations split at control changes | Present where a change occurred |

## Sampling

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Method | sample size and selection method | Documented before testing |
| Seed or list | the selection seed or the full sample list | Retained |
| Coverage | sample as a fraction of population | Justified for the control's risk |

## Evidence and Conclusion

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Per-sample evidence | evidence reference per instance | Present, including exceptions |
| Disposition | pass / fail / exception per sample | Recorded |
| Conclusion split | design versus operating effectiveness stated separately | Present |

## Telemetry Prerequisites

- A system extract that defines the population, since completeness is the first audit question.
- A retained-evidence repository per control, because evidence reconstructed after the fact is weak.
- An exception workflow, so a failed sample produces a remediation item rather than a footnote.

## Deployment Gates

- No operating-effectiveness conclusion without a population definition and per-sample evidence.
- Design and operating conclusions are reported separately; combining them is rejected.
