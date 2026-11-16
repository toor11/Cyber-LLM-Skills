# Detection Queries and Telemetry Artifacts

> Sub-skill: [`hypothesis-driven-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Hypothesis-register checks. Each row names the record field and the state a useful register shows.

## Statement

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Mechanism | hypothesis record with a `because` clause naming the technique mechanism | Present |
| Population and window | scope fields with counts and dates | Explicit, not 'the estate' |
| Falsification | `falsification` field with its coverage requirement | Present before the query runs |

## Prioritisation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Cost of being wrong | impact rating per hypothesis | Recorded and used for ordering |
| Baseline noise estimate | expected false-positive volume from the baseline | Low-noise hypotheses first |
| Duplication check | existing rule ids covering the same observable | None, or the hunt explicitly extends coverage |

## Closure

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Outcome class | confirmed / absent / unanswerable | Recorded with evidence |
| Gap ticket | unanswerable hypotheses with a coverage ticket | 100% |

## Telemetry Prerequisites

- A detection library you can search, so hypotheses are not duplicating existing coverage.
- Baseline data over a period before the activity of interest.
- A register that persists hypotheses, because the ranking and the null results are the value.

## Deployment Gates

- No hypothesis is executed without a written falsification condition.
- Unanswerable hypotheses generate a coverage ticket rather than being quietly closed.
