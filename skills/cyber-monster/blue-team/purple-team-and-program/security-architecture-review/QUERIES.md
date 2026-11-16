# Detection Queries and Telemetry Artifacts

> Sub-skill: [`security-architecture-review`](SKILL.md) | Family: **Purple Team and Program**

Architecture-review checks. Each row names the artefact and the state a defensible review shows.

## Placement

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Visibility | what each control can inspect for the data class | Recorded per hop |
| Bypass paths | paths to the data store that skip a control | Enumerated from logs and code |
| Effective control | the weakest path to each data store | Identified |

## Failure

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Documented mode | fail-closed / fail-open / degrade per control | Present |
| Probe result | behaviour with the dependency unavailable | Recorded |
| Compensating detection | detection for fail-open controls | Present |

## Telemetry Prerequisites

- As-built configuration and flow logs, since the intended diagram is the least reliable input.
- A data-classification list, so placement can be judged against the data.
- A way to stop or block the control's dependency in a test environment.

## Deployment Gates

- No control is signed off without a documented failure mode.
- Every bypass path found is either closed or recorded with an owner and an exposure note.
