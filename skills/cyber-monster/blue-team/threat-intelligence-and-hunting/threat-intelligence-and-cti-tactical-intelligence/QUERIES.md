# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-intelligence-and-cti-tactical-intelligence`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Tactical product checks. Each row names the field and the state a usable product shows.

## Statement Quality

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Implementation | binary, protocol, or artefact named | Present for every TTP |
| Observable | field-level description | Present and mapped to a log source |
| Verdict | detectable / gap / not tactical | One per TTP |

## Detectability

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Baseline frequency | measured frequency of the observable | Recorded before any detection recommendation |
| Secondary condition | additional field narrowing ubiquitous observables | Specified where needed |
| Log source coverage | collection status per source | Explicit, with gap tickets |

## Currency

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| ATT&CK version | version recorded with the mapping | v19 or later |
| Tactic placement | tactic recorded per technique | Stealth or Defense Impairment, not Defense Evasion |

## Telemetry Prerequisites

- Field-level query access, since baseline frequency cannot be estimated from a report.
- A log-source inventory with coverage percentages.
- The current ATT&CK release, so technique ids and tactics are not stale.

## Deployment Gates

- No TTP enters the detection backlog without an observable and a baseline frequency.
- Coverage gaps are ticketed with the log source named, not folded into the detection backlog.
