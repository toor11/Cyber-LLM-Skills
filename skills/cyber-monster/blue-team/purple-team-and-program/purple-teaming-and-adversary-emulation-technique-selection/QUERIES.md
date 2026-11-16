# Detection Queries and Telemetry Artifacts

> Sub-skill: [`purple-teaming-and-adversary-emulation-technique-selection`](SKILL.md) | Family: **Purple Team and Program**

Selection-record checks. Each row names the field and the state a defensible list shows.

## Relevance

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Source per technique | report or incident reference | Present, dated within the planning horizon |
| Platform fit | technique platform versus estate platform | Matches |

## Coverage

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Analytic presence | rule id or explicit none | Recorded |
| Last validation | date of the last successful validation | Older than the planning horizon, or absent |
| Gap reason | why the existing analytic does not cover it | Recorded |

## Safety

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Classification | safe / needs isolation / tabletop only | One per technique |
| Environment | where the emulation will run | Matches the classification |
| Cleanup | how the technique is reversed | Defined before the window |

## Telemetry Prerequisites

- Sector-specific intelligence, since generic prevalence is not relevance.
- A searchable detection library with last-validation dates.
- An isolated range or an approved window for any unsafe classification.

## Deployment Gates

- No technique enters the plan without a relevance source and a coverage verdict.
- Unsafe techniques are never emulated in production, regardless of relevance.
