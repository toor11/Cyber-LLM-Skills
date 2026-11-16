# Operational Triage and Response Playbook

> Sub-skill: [`ransomware-response`](SKILL.md) | Family: **Incident Response**

Structured runbook for `ransomware-response`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

This playbook is victim-side only. It covers scope, preservation, recovery readiness and the disclosure decision. It does not cover communication with an actor, payment mechanics or any negotiation step; those route to counsel, the cyber insurer and law enforcement, and the record of them is kept outside this library.

## Triggers

- Users report files that will not open, renamed with an unfamiliar extension, or a note placed in directories.
- A backup, hypervisor or file-server monitor alarms on mass renames, shadow-copy deletion or a recovery-agent tamper.
- An external party — insurer, law enforcement, a partner, a customer — reports activity on the estate before internal telemetry shows it.
- Threat intelligence names a current #StopRansomware campaign and the estate matches its target profile, without encryption yet observed.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| New extension plus write burst on two or more hosts, note present | Confirmed Ransomware | Isolate at segment boundary, capture memory on one representative host, freeze backups |
| Shadow-copy deletion or backup-agent stop with no encryption yet | Confirmed Pre-Impact - highest urgency | Preserve and isolate now; this stage precedes impact and the window to act is short |
| Burst with no new extension and a matching scheduled job | Benign Baseline | Record the job identifier; narrow the exclusion to that job, not the whole rule |
| A note with no encryption, no access change and no write burst | Unconfirmed Claim | Treat as a hoax or leftover; do not invoke recovery until file state is verified |
| Encryption observed, no egress evidence, actor claims data theft | Confirmed Ransomware - exfiltration unproven | Route the exfiltration question to `raas-extortion-and-negotiation-triage`; keep the claim labelled |
| Encryption on a segment with no agent coverage | Inconclusive - Scope Unknown | Declare the segment unmeasured and treat it as in scope for isolation |
| Restore point predates the earliest pre-impact artifact and is immutable | Recovery Available | Proceed to `ransomware-response-recovery-and-restore`; do not restore before vector closure |

## Containment and Recovery

1. **Preserve before mutating, and sequence memory capture against spread.** If encryption is still advancing, isolate at the segment or VLAN boundary first and accept partial host capture, recording which hosts were captured and which were not. If spread has stopped, capture volatile state on a representative host of each role before any isolation.
2. **Establish decision authority before the first irreversible act.** Name who may authorise isolation of a domain controller, a hypervisor cluster or the backup tier, and record the name and time of each authorisation. An incident that stalls on authority loses hosts.
3. **Decide legal hold explicitly, and record the reasoning.** A hold obliges preservation of the artifacts that date the disclosure obligation; it does not forbid isolation. Write down which one you chose and why, so the decision is auditable rather than reconstructed later.
4. **Verify recovery capability read-only before promising a date.** Confirm the last pre-incident restore point, its immutability state and whether a restore test has ever succeeded. A recovery date promised from a backup that has never been restored is a guess presented as a plan.
5. **Close the entry branch, not just the host.** An edge-appliance credential, a VPN account or a mail token that remains valid re-enters the rebuilt estate. Confirm closure with a post-change authentication attempt that fails, not with the ticket marking the change done.
6. **Escalate, do not negotiate.** Law enforcement notification, insurer engagement and any sanctions or disclosure screening belong to counsel and the executive owner. This skill's job is to hand them an evidence package with onsets, scope, exfiltration status and recovery state clearly labelled by confidence.
