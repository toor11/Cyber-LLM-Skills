# Operational Triage and Response Playbook

> Sub-skill: [`ransomware-response-recovery-and-restore`](SKILL.md) | Family: **Incident Response**

Structured runbook for `ransomware-response-recovery-and-restore`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

Victim-side recovery only. No decryptor sourcing, payment mechanics or actor communication content.

## Triggers

- Containment is declared complete and the business wants a restore date.
- A backup tier has been found in scope, or an immutability claim needs verification.
- A restored host behaves abnormally, re-encrypts, or contacts an unfamiliar destination.
- A recovery exercise or audit asks for evidence that the restore path actually works.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Point predates the earliest pre-impact artifact, target immutable and separated, closure tested | Recovery Available | Restore in dependency order with a stated observation window |
| Point exists but only after the implant landed | Recovery Blocked - Contaminated Point | Data-only recovery into a rebuilt platform, or an older full; never a full restore |
| Repository reports no immutable interval | Control Gap - Mutable Target | Treat as suspect, validate from an isolated copy, and fix the lock configuration as an action item |
| Entry vector untested or tested with an unrelated failure | Recovery Blocked - Closure Unproven | Return to containment; do not restore into an open path |
| Restored host re-encrypts inside the observation window | Restore Failed - Re-entry | Halt further restores, return to containment, identify the surviving path |
| Restore reports success but file counts or sample hashes diverge | Control Gap - Fidelity Unverified | Re-run with the selection policy in hand before declaring recovery |
| Post-restore telemetry absent | Inconclusive - Observation Impossible | Do not close recovery; onboard coverage or extend observation |

## Containment and Recovery

1. **Order restore by dependency, not by business volume.** Identity and DNS first, then the services that authenticate against them, then application tiers, then data. Restoring a business-critical application before its identity dependency produces a host that authenticates against a still-compromised domain controller.
2. **Verify closure before the first byte.** A failed re-authentication through the original vector, with the failure reason recorded, is the gate. Schedule pressure is not a reason to skip it; a second encryption event costs more time than the test.
3. **Restore into a validated platform when the platform itself is untrusted.** Rebuild from known-good media or a golden image, then restore only data. Restoring an operating system from a point that predates the implant but postdates an older resident backdoor reinstates the backdoor.
4. **Define the per-host observation window and its failure condition in writing before restore starts.** State the duration, the signals watched, and who decides that a re-contact ends recovery. An observation window that nobody defined is closed by whoever is tired.
5. **Record the restore as a measured fact set, not a status.** Point timestamp, target lock state, closure test result, per-host observation outcome and fidelity sample result belong in one artefact — the post-incident review will need exactly these, and reconstructing them later is guesswork.
