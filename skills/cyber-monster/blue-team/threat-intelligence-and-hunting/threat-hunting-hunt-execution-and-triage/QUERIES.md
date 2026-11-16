# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-hunting-hunt-execution-and-triage`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Triage-record checks. Each row names the field and the state a defensible triage shows.

## Clustering

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Cluster key | grouping fields used (host, parent, account, destination) | Recorded, so another analyst can regroup |
| Cluster size | events and hosts per cluster | Both reported; one without the other is ambiguous |

## Evidence

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Process ancestry | EID 1 parent/child chain for endpoint clusters | Captured for escalating clusters |
| Account context | account, logon type, and source host | Present |
| External correlation | indicator or campaign match | Recorded with the source |

## Disposition

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Baseline frequency | count in the baseline window per cluster | Present before any benign verdict |
| Outcome class | escalate / baseline / coverage gap | One per cluster |
| Owner | assignee per escalating cluster | Named |

## Telemetry Prerequisites

- Saved raw query output, since triage decisions must be reproducible.
- Baseline window results for the same query, so frequency comparison is possible.
- Endpoint telemetry (process creation with parent) to resolve ambiguous clusters.

## Deployment Gates

- No cluster is marked benign without its baseline frequency recorded.
- Sensor gaps produce a coverage ticket, never a benign disposition.
