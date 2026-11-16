# Detection Queries and Telemetry Artifacts

> Sub-skill: [`purple-teaming-and-adversary-emulation-execution-and-validation`](SKILL.md) | Family: **Purple Team and Program**

Validation-record checks. Each row names the field and the state a reproducible record shows.

## Execution Bounds

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Window | emulation start and end timestamps with timezone | Recorded per technique |
| Target hosts | explicit host list | Recorded, matching the safety scope |
| Preconditions | prerequisite check result | Recorded; unmet means inconclusive |

## Evidence

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Captured events | event ids with timestamps and a file reference | Present |
| Analytic evaluation | rule id and evaluation time | Present, including no-match |
| Alert record | alert id and time where detected | Present where detected |

## Outcome

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Outcome class | detected / logged-not-detected / absent | One per technique |
| Latency | event-to-alert seconds | Recorded where detected |
| Owner and action | assignee per gap with a ticket | Present |

## Telemetry Prerequisites

- Live telemetry access during the window, so the analytic evaluation can be traced.
- The baseline query result from immediately before the emulation.
- The analytics' filter logic available for inspection, since a no-match needs a reason.

## Deployment Gates

- No result is recorded without a baseline captured in the preceding 24 hours.
- Every gap has an owner and a re-run date; a ticket without a re-run is not closure.
