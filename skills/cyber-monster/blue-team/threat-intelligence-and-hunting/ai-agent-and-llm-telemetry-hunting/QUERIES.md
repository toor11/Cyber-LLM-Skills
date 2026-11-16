# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ai-agent-and-llm-telemetry-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

AI telemetry hunt checks. Each row names the field and the state a hunt-ready platform shows.

## Telemetry Inventory

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Tool call identity | `caller.id` and `credential.scope` per tool call | Both present |
| Retrieval tenant | `chunk.tenant_id` and `request.tenant_id` | Both present for comparison |
| Egress | `network.destination` for tool-runtime connections | Present, with the process image |

## Baseline

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Tool mix | per-tool call share over the baseline window | Recorded per agent |
| Token distribution | p50 and p99 per request | Recorded, so spikes are relative |
| Destination set | normal outbound hosts | Enumerated and allowlisted |

## Differential

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Staging injection | observable change under an injected document | Recorded; if absent, the hunt question is unanswerable |
| Gap ticket | missing fields with an onboarding ticket | Present |

## Telemetry Prerequisites

- Structured tool-call logging with caller identity, which is the only way to compare entitlement to use.
- A staging corpus where an injection can be placed, so the differential exists.
- A destination allowlist, so egress anomalies have a reference point.

## Deployment Gates

- No hunt is declared clean when the fields it needs are missing; the output is a coverage ticket.
- Every agent has a recorded baseline before its first hunt.
