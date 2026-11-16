# Operational Triage and Response Playbook

> Sub-skill: [`windows-artifact-forensics-execution-artifacts`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `windows-artifact-forensics-execution-artifacts`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `prefetch analysis`.
- Alert, hunt outlier, or review request matching `shimcache`.
- Alert, hunt outlier, or review request matching `amcache`.
- Alert, hunt outlier, or review request matching `srum`.
- A remote-access tool appears on a host with no change ticket and the question is whether it ran.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Prefetch last-run and an SRUM row for the same path within one minute, plus a non-system volume serial | Confirmed Execution | Preserve Prefetch, SRUM and the SOFTWARE hive together; pivot on the SID for lateral movement |
| Prefetch entry with run count above one at a fixed interval, matching a scheduled task | Confirmed Persistence (Execution Confirmed) | Export the task definition and its `$MFT` entry before any cleanup; the cadence is the persistence evidence |
| Amcache row with a hash but no Prefetch and no SRUM row, and `SysMain` was stopped for the window | Inconclusive (Telemetry Gap) | Report identity only; do not state execution, and record the `SysMain` state as the reason |
| ShimCache entry for a path with the `Executed` flag false on a modern build | Presence Only | Do not report execution; pivot to Prefetch, SRUM or 4688 for a run |
| SRUM row dated before the artefact's retained boundary | Out of Coverage | Exclude from the matrix; a pre-boundary absence is a retention artefact, not a finding |

## Containment and Recovery

1. **Preserve before mutating:** collect Prefetch, `SRUDB.dat` with its transaction logs, Amcache with `.LOG1`/`.LOG2`, and the SOFTWARE hive together; parsing any one of them later without the others reduces the claim from execution to presence.
2. **Capture the service state:** record `SysMain` status and start type at acquisition time, because it determines whether an empty Prefetch directory is meaningful.
3. **Preserve the medium identity:** the Prefetch volume serial is often the only remaining proof that an image ran from removable or mounted media, and it disappears with the file.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
