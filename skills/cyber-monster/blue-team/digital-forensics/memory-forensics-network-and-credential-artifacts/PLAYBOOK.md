# Operational Triage and Response Playbook

> Sub-skill: [`memory-forensics-network-and-credential-artifacts`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `memory-forensics-network-and-credential-artifacts`. Paired offensive/mechanics reference: [`credential-dumping`](../../../red-team/network-ad-and-endpoint/credential-dumping/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `memory network artifacts`.
- Alert, hunt outlier, or review request matching `credential extraction memory`.
- An EDR or NGFW flow record names a remote endpoint on a host whose on-disk logs show no matching process creation.
- A privileged account is used from a host where the account never logged on interactively.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Pool socket whose owning PID resolves to a user-writable image path, plus an independent flow record for the same remote tuple inside one UTC minute | Confirmed Malicious | Preserve the image and the flow record together; scope every host that beaconed to the same remote tuple before any containment |
| `hashdump` and `lsadump` populated as expected for the host's join type, no foreign endpoint, no anomalous owner | Benign Baseline | Record the account population as the baseline for this build and role; re-baseline after any agent rollout |
| `netscan` returns zero rows while `windows.info` resolved cleanly | Inconclusive (Parser or Symbol Gap) | Do not record it as a quiet host; run `windows.netstat` and `windows.psscan`, and check the pool-constraint fit for the build |
| `cachedump` empty on a host confirmed as workgroup-joined | Structurally Empty Source | Exclude the source from the finding matrix rather than scoring it as a negative |
| Autologon `DefaultPassword` populated, no other artefact | Control Gap (Exposure) | Treat as a credential-at-rest finding; rotate the secret and disable autologon, do not open a malware case on the strength of it alone |

## Containment and Recovery

1. **Preserve before mutating:** hash and copy the memory image and the matching flow records before touching the host; a reboot destroys every pool object this skill depends on.
2. **Contain the remote tuple, not just the host:** scope the destination address and port across the fleet using flow data, because the socket differential only names one host.
3. **Rotate before eradicating:** any account whose verifier was resident in the image must be treated as disclosed; rotate credentials and invalidate sessions before rebuilding, or the rebuild will be re-compromised through the same secret.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
