# Detection Queries and Telemetry Artifacts

> Sub-skill: [`purple-teaming-and-adversary-emulation`](SKILL.md) | Family: **Purple Team and Program**

Exercise-record checks. Each row names the field and the state a measured exercise shows.

## Preparation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Prediction record | expected event and analytic per technique, dated before the window | Present for every technique |
| Baseline capture | same query over the prior 24h | Recorded as zero or known count |
| Safety agreement | scope, prohibitions, stop authority | Written and acknowledged |

## Execution

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Probe evidence | event ids or query output per technique | Captured during the window |
| Outcome class | detected / logged-not-detected / absent | One per technique |
| Timing | alert latency from event to detection | Recorded where detected |

## Closure

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Action per gap | detection change or accepted gap with ticket | Present |
| Re-run record | same emulation after the change | Present for every closed gap |

## Telemetry Prerequisites

- A safe emulation method per technique, agreed with the platform owners.
- Telemetry access during the window, so the probe can be observed live.
- A named stop authority reachable by voice, not only by ticket.

## Deployment Gates

- No technique is emulated without a recorded prediction.
- Every gap closes with a re-run, not with a ticket alone.
