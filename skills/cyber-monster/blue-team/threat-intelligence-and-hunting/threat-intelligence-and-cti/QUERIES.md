# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-intelligence-and-cti`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Product-quality checks. Each row names the field or artefact and the state a defensible product shows.

## Requirement

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Consumer and decision | PIR records with `consumer`, `decision`, `expires` | All three populated |
| Decision linkage | products cited in decision or change records | At least one per PIR per cycle |
| Stale requirements | PIRs past `expires` | Retired or re-scoped, not silently renewed |

## Assessment Quality

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Estimative statement | the judgement sentence separate from the evidence block | Present, and phrased as a judgement |
| Confidence rationale | source count and corroboration behind the level | Recorded; single source never rated high |
| Evidence dates | date on every cited observation | Present, so staleness is visible |

## Mapping Currency

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| ATT&CK version | version recorded with each mapping | v19 or later, with the Stealth/Defense Impairment split applied |
| Sub-technique discipline | use of sub-technique ids | Parent ids only, since the taxonomy cap is three parents |

## Telemetry Prerequisites

- A requirements register with consumers named, since intelligence without a customer has no success criterion.
- A source log recording retrieval dates, so assessments can be re-derived.
- Telemetry that can corroborate external reporting, which is what raises confidence above moderate.

## Deployment Gates

- No product ships without an estimative statement and a confidence level.
- Every PIR names the decision it informs; a PIR that cannot is retired.
