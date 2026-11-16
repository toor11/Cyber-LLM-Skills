# Detection Queries and Telemetry Artifacts

> Sub-skill: [`soc-operations-and-shift-process`](SKILL.md) | Family: **Purple Team and Program**

SOC process checks. Each row names the metric or artefact and the state a measurable operation shows.

## Queue Design

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Tier entry criteria | published criteria per queue | Present and identical across shifts |
| Enrichment separation | alerts routed to enrichment before triage | Present where joins are needed |
| Backlog ageing | items older than the tier SLA | Visible and assigned |

## Decision Record

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Closure reason | reason from the closed list per closure | 100% |
| Evidence | evidence reference per closure | Present for true positives and benign-unexpected |
| Distribution | closure-reason mix per period | Tracked; insufficient_data trends down after tuning |

## Continuity

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Handover state | current state and next action per item | Present |
| Ownership | named owner across the shift boundary | Unchanged or explicitly transferred |
| Escalation path | named escalation contact with a time | Present |

## Telemetry Prerequisites

- A ticketing system that enforces a closure-reason field, since free text cannot be measured.
- Enrichment lookups available to tier 1, so investigation work is not pushed upstream.
- A published runbook with entry criteria and escalation thresholds.

## Deployment Gates

- No closure without a reason from the closed list and an evidence reference where applicable.
- Handovers are written and stateful; verbal handover alone is not accepted for open investigations.
