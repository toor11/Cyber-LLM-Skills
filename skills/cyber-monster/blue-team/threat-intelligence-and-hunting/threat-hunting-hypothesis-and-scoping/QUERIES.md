# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-hunting-hypothesis-and-scoping`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Scope-record checks. Each row names the field and the state a defensible scope shows.

## Population

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Counts | host and account counts with inventory date | Present and dated |
| Exclusions | excluded classes with reason and owner | Recorded per class |
| Inventory source | system the population came from | Named, not 'the CMDB' generically |

## Coverage

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Per-host events | count of the target event per host | Every host above zero, or listed as a gap |
| Sensor version | agent version reporting the event | Consistent within the population |
| Retention | oldest available event for the source | Covers the whole window |

## Design

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Window pairing | baseline and probe windows with dates | Baseline precedes probe |
| Interpretation | pre-committed reading of a null result | Written before execution |

## Telemetry Prerequisites

- A dated inventory extract, since scope built from a stale inventory silently misses assets.
- Per-host telemetry visibility, which most SIEMs expose as a host coverage view.
- The retention policy for the source, so window choices are honest.

## Deployment Gates

- No hunt runs without a per-host coverage count for its target event.
- Exclusions always carry an owner; unexplained exclusions become findings.
