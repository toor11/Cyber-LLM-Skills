# Detection Queries and Telemetry Artifacts

> Sub-skill: [`darkweb-and-underground-monitoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Monitoring-programme checks. Each row names the record field and the state a governed programme shows.

## Scope and Handling

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Scope record | targets and legal basis | Present before collection |
| Retention | raw artefact retention period | Defined; expired material deleted |
| Minimisation | individual-level data retained | Only what the action requires |

## Verification

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Discriminator | domain, tenant id, or unique identifier | Recorded per finding |
| Control comparison | same search against an unrelated brand | Present |
| Credential testing | whether passwords were tested against systems | Never; existence checks only |

## Action

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Action type | reset, control verification, incident | Recorded with an owner |
| Closure | confirmation the action completed | Present |

## Telemetry Prerequisites

- Written legal basis and handling rules, since collected material contains third-party personal data.
- A credential-exposure service or leak-site index feed that does not require community participation.
- An identity team able to execute forced resets and session revocation.

## Deployment Gates

- No password is ever tested against a live system from collected material.
- Raw artefacts expire on schedule; findings retain actions rather than personal data.
