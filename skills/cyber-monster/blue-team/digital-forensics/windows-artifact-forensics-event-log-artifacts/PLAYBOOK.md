# Operational Triage and Response Playbook

> Sub-skill: [`windows-artifact-forensics-event-log-artifacts`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `windows-artifact-forensics-event-log-artifacts`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `event log forensics`.
- Alert, hunt outlier, or review request matching `sysmon analysis`.
- Alert, hunt outlier, or review request matching `windows event ids`.
- A detection fires on 4688 parent-child pairing and the analyst must confirm it from the raw channel.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| 4688 or Sysmon 1 for a child in a user-writable directory under a signed system parent, corroborated by a filesystem artefact naming the same image within seconds | Confirmed Malicious | Preserve the exported channels and the filesystem artefact together; derive the parent process tree before containment |
| Complete reassembled 4104 containing a download-and-execute sequence, with an execution artefact for the same interval | Confirmed Malicious | Quote the reassembled block with its `ScriptBlockId`; treat the script content as the primary artefact and the execution as corroboration |
| Empty 4688 set with process-creation auditing disabled for the window | Inconclusive (Audit Policy Gap) | Pivot to Sysmon or execution artefacts; record the gap as a detection-engineering action, never as a clean result |
| Record-ID discontinuity with an archived `.evtx` of the expected size and no 1102 | Normal Rotation | Confirm against the configured maximum log size before describing the gap as tampering |
| 4624 type 3 burst from one machine account matching that account's baseline for the same hour | Benign Baseline | No action; add the account and destination pair to the baseline note for the next hunt |

## Containment and Recovery

1. **Preserve before mutating:** export every channel with `wevtutil epl` and hash the exports before touching the host; live queries lose record identity that later review needs.
2. **Fix the denominator, not just the case:** an audit-policy gap found during triage becomes a configuration change so the next incident is answerable.
3. **Preserve the Sysmon configuration:** the running configuration version determines which events could exist, so capture it alongside the logs.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
