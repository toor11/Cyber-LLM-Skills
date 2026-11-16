# Detection Queries and Telemetry Artifacts

> Sub-skill: [`indicator-lifecycle-and-ioc-management`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Lifecycle health checks. Each row names the field and the state a managed programme shows.

## Classification and TTL

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Class coverage | indicators with an observable class | 100% |
| TTL enforcement | indicators past TTL still deployed | Retired or re-justified |
| Class-appropriate life | TTL by class | Hashes long, network indicators short |

## Discrimination

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Hit attribution | hits per indicator split by asset and incident | Recorded; scanner traffic excluded |
| Benign reclassification | hits later judged benign | Counted, and the indicator re-scoped or retired |
| Alert-to-incident ratio | alerts per confirmed incident by indicator | Improving after retirement cycles |

## Provenance and Sharing

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Source | indicators with a named source | 100% |
| Sharing constraints | TLP or licence field | Present where the source requires it |
| Internal context leakage | exported indicators containing internal hostnames | Zero |

## Telemetry Prerequisites

- Hit tracking per sensor, since discrimination cannot be measured from the indicator store alone.
- A scanner and authorised-activity list, so those hits can be excluded from scoring.
- A retirement queue, because retirement is a decision that needs review like any other.

## Deployment Gates

- No indicator is deployed without a class, a source, and a TTL.
- Retirement is reviewed on evidence, and a retired indicator stays queryable for retrospective hunts.
