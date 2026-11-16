# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Hunt-execution checks. Each row names the record or field and what a defensible hunt shows.

## Hypothesis Quality

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Observable and sequence | hypothesis text naming fields and ordering | Both present |
| Population | scope definition (hosts, accounts, window) | Explicit count and window |
| Falsifiability | the condition that would disprove it | Stated before the query runs |

## Data Adequacy

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Event availability | target event count per host in the window | Non-zero for every host in scope |
| Field population | null rate for the fields the hypothesis needs | Low enough to answer |
| Retention | oldest available event for the source | Covers the window |

## Outcome

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Baseline | baseline window result | Quiet, with the exclusion list derived from it |
| Disposition | hunt record with yes/no/unanswerable | Recorded with evidence |
| Conversion | rule id or coverage ticket linked from the hunt | At least one per completed hunt |

## Telemetry Prerequisites

- Query access to the relevant telemetry with the fields the hypothesis needs.
- A baseline period before the activity of interest, so rarity can be measured.
- A rule repository or coverage register, so a positive hunt has somewhere to land.

## Deployment Gates

- No hunt closes as 'clean' without a data-adequacy check recorded.
- Every positive hunt produces either a detection or a documented, accepted gap.
