# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secrets-management-and-key-custody`](SKILL.md) | Family: **Application Security**

Secret exposure and custody checks. Each row names the place to look and the property it proves.

## Exposure Surface

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Repository history | secret scanner over full history, not only the working tree | No live material; historical hits have a rotation record |
| Image layers | `docker history` and layer content scan | No `ENV`/`ARG` carrying material |
| CI configuration | workflow variables referenced in forked-PR contexts | Zero secrets reachable from untrusted triggers |
| Logs | log store search for key prefixes and bearer tokens | Zero unredacted matches |

## Custody

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Reader identity | store audit entry for the workload | Attributable identity per read, not a shared admin token |
| Scope | policy attached to the secret path or role | Least privilege per workload; no wildcard path |
| Material in config | manifests containing `value:` for a credential field | Zero; references only |

## Rotation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Rotation probe | rotate then restart without rebuild | New version read, old version rejected |
| Dual-version overlap | store allowing two active versions during rotation | Enabled for zero-downtime rotation |
| Expiry metadata | secrets with a `rotation_due` field | Within the documented cryptoperiod |

## Telemetry Prerequisites

- Read access to the secret store's audit log, since custody is proven by reads not by policy documents.
- The ability to rotate one test secret end to end, which is what makes the rotation probe possible.
- A list of the workloads and their expected identities, to detect shared credentials.

## Deployment Gates

- Any secret without a rotation path is registered as accepted risk with an expiry and an owner.
- A leaked secret is rotated before any history rewrite is attempted; the rotation record is the closure evidence.
