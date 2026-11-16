# Detection Queries and Telemetry Artifacts

> Sub-skill: [`indicator-lifecycle-ioc-deployment-retirement`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Deployment health checks. Each row names the artefact and the state a managed deployment shows.

## Placement

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Class-to-control mapping | indicator class versus control type | Every class has a control that can observe it |
| Scope | direction and population per deployment | Explicit; not 'everywhere' |
| Exemptions | allowlist entries for shared infrastructure | Present where the class requires them |

## Mode and Proof

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Mode | enforce versus alert per control | Matches specificity and validation state |
| Probe result | synthetic match per deployment | Fires, with a timestamp |
| Hit history | hits per control per cycle | Recorded; no-hit indicators are reviewed rather than assumed effective |

## Retirement

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| TTL | retirement date per indicator | Inside the class TTL |
| Retention | retired records still queryable | Yes, with status=retired |
| Enforcement removal | rules absent after retirement | Verified with a probe |

## Telemetry Prerequisites

- An inventory of enforcement controls by observable class, so placement can be decided rather than guessed.
- A synthetic probe method per control, since unproven enforcement is the common failure.
- A store that keeps retired indicators queryable for retrospective hunts.

## Deployment Gates

- No indicator is enforced without a synthetic probe confirming the control fires.
- Retirement removes enforcement and keeps the record; deletion is not an acceptable retirement.
