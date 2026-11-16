# Detection Queries and Telemetry Artifacts

> Sub-skill: [`remediation-tracking-and-verification`](SKILL.md) | Family: **Purple Team and Program**

Tracker health checks. Each row names the field and the state a verifiable programme shows.

## Ownership and Dates

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Owner | assignee per open item | 100% populated |
| Date basis | due date derived from KEV/exposure evidence | Recorded with its basis |
| Ageing | open items past their due date | Escalated, not silently extended |

## Closure Rules

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Rule per class | closure rule field per finding class | Present |
| Probe artefact | verification file or query output per closed item | Present |
| Baseline evidence | original evidence retained | Present, so the probe can be compared |

## Reopen

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Reopen trigger | condition that reopens the item | Defined per class |
| Recurrence | items reopened after closure | Tracked as a quality signal |

## Telemetry Prerequisites

- A verification method per finding class, since a generic 'verified' field invites status closure.
- Storage for probe artefacts linked to the item, because the artefact is the closure.
- A reopen workflow, so recurrence is visible rather than re-ticketed as new.

## Deployment Gates

- No item closes without a stored probe artefact matching its class.
- Recurrence rates are reported; a high rate means the fixes are not addressing the cause.
