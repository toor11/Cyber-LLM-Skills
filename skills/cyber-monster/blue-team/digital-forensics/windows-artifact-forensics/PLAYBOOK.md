# Operational Triage and Response Playbook

> Sub-skill: [`windows-artifact-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `windows-artifact-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `windows forensics`.
- Alert, hunt outlier, or review request matching `windows artifacts`.
- Alert, hunt outlier, or review request matching `prefetch`, `shimcache` or `usn journal`.
- An investigation needs a defensible statement about what a Windows host did, when, and as whom.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Readiness matrix shows a usable execution pair, and the Prefetch/SRUM join attributes a non-system image to a SID inside the window | Confirmed Execution and Attribution | Preserve the triage set and the join output; scope other hosts using the same image hash |
| Readiness matrix shows `Prefetch` absent, `SRUM` absent and no 4688 channel | Inconclusive (Telemetry Gap) | State the gap and pivot to filesystem artefacts; do not report a clean execution history |
| Autostart value new to this host with a `LastWrite` inside the window, backed by a registry-write event | Confirmed Persistence | Export the referenced binary and its `$MFT` record before any cleanup |
| Every artefact differs from the peer host only by hostname and install time | Benign Baseline | Record the peer host used and close as baseline; refresh the baseline after the next software rollout |
| Bare journal `BasicInfoChange` joined to an `$SI`/`$FN` discrepancy on the same record | Confirmed Anti-Forensic Activity | Report the rewrite time and pivot to the process that performed it via execution artefacts |

## Containment and Recovery

1. **Preserve before mutating:** collect the triage set with hashes, and keep the readiness matrix with the case so a reviewer can see which absences were coverage rather than evidence.
2. **Order the collection:** volatile state first, then hives with their logs, then event channels, then the filesystem metadata; each step after the first reads from a copy.
3. **Close the coverage gaps you found:** a `SysMain` disablement, an audit subcategory that was off, or a KAPE target that omitted `SRUDB.dat` becomes a configuration action, so the next case is answerable.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
