# Detection Queries and Telemetry Artifacts

> Sub-skill: [`compliance-mapping-and-reporting`](SKILL.md) | Family: **Purple Team and Program**

Crosswalk-quality checks. Each row names the field and the state a defensible mapping shows.

## Version Discipline

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Framework versions | edition and release date per framework | Present and current |
| Revision watch | date the mapping was last validated against the framework | Inside the review cycle |

## Mapping

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Single primary | clauses with more than one primary control | Zero |
| Coverage | applicable clauses without a control or a justification | Zero |
| Not applicable | exclusions with justification | 100% justified |

## Evidence

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Evidence path | path or query per clause for the period | Present |
| Exception record | compensating control per exception | Present |
| Third-party inspectable | evidence a reviewer can open | Yes, with retention |

## Telemetry Prerequisites

- The framework editions in scope, with their release dates.
- A control register with owners and tests, since the mapping terminates there.
- An evidence repository organised by control and period.

## Deployment Gates

- No clause is reported satisfied without a test type and an evidence path.
- Framework version upgrades trigger a re-validation of every mapping in that framework.
