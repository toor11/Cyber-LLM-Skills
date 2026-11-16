# Detection Queries and Telemetry Artifacts

> Sub-skill: [`osint-for-defenders`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Collection-programme checks. Each row names the artefact and the state a governed programme shows.

## Scope and Legality

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Scope record | domains, brands, and patterns with a legal basis | Present before collection |
| Passive-only boundary | collection methods used | No interaction with third-party hosts |
| Individual data | any person-level collection | Absent, or with a documented purpose |

## Verification

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Evidence artefact | saved page, CT entry, or screenshot with a retrieval date | Present per finding |
| Control comparison | same query against a known-clean brand | Recorded to rule out search artefacts |
| Scope of exposure | what the finding actually reveals | Verified, not inferred from the title |

## Action

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Owner | assignee per finding | Named |
| Action type | takedown, revoke, rotate, monitor | Recorded with a date |
| Closure | verification that the item is gone or the key revoked | Present |

## Telemetry Prerequisites

- A documented legal basis for the collection scope, since brand and person data differ legally.
- Storage for evidence artefacts with retrieval dates, because public pages disappear quickly.
- A takedown process or vendor, since discovery without a removal path is incomplete.

## Deployment Gates

- No interaction with impersonating infrastructure beyond passive observation and reporting.
- Every finding carries a verification artefact; unverified search hits are not findings.
