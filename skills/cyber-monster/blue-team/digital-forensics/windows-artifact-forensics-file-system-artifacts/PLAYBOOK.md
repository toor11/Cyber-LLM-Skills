# Operational Triage and Response Playbook

> Sub-skill: [`windows-artifact-forensics-file-system-artifacts`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `windows-artifact-forensics-file-system-artifacts`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `mft forensics`.
- Alert, hunt outlier, or review request matching `usn journal analysis`.
- Alert, hunt outlier, or review request matching `recycle bin forensics`.
- An analyst needs to establish when a file appeared, changed or vanished on an NTFS volume.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Bare `BasicInfoChange` on a file reference joined to an `$SI` earlier than `$FN` on the same record, with zeroed subseconds | Confirmed Anti-Forensic Activity | Preserve the journal parse and the MFT row together; pivot to the process that performed the write via execution artefacts |
| `FileDelete` followed by `FileCreate` reusing the name, in a case-relevant directory, with the payload unallocated | Confirmed Concealment | Recover the unallocated content by inode before any further writes to the volume |
| `$SI` earlier than `$FN` on files under an installer's staging directory, with a matching install burst | Benign Baseline (Installer) | Record the installer path pattern in the baseline; do not report timestomping for that directory class |
| Journal whose oldest USN postdates the incident window | Inconclusive (Coverage Boundary) | Reconstruct from `$LogFile` if it covers the window, otherwise state the gap and pivot to event logs |
| Recycle bin empty with a policy that clears it on logoff | Inconclusive (Configuration) | Do not report a deletion finding; pivot to the journal for the actual delete records |

## Containment and Recovery

1. **Preserve before mutating:** capture `$MFT`, `$J` and `$LogFile` together with a volume-level hash; any further write to the volume evicts journal records permanently.
2. **Recover content early:** unallocated clusters holding a deleted payload are overwritten by ordinary system activity, so recovery by inode should precede further analysis on a copy.
3. **Record the coverage boundary:** the USN range and `$LogFile` earliest entry belong in the report, because a later reviewer cannot recompute them from the parsed output.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
