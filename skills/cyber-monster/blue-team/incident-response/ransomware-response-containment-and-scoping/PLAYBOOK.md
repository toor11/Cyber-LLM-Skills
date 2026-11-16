# Operational Triage and Response Playbook

> Sub-skill: [`ransomware-response-containment-and-scoping`](SKILL.md) | Family: **Incident Response**

Structured runbook for `ransomware-response-containment-and-scoping`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

Victim-side scope and containment only. No actor communication, payment reasoning or negotiation content belongs in this file.

## Triggers

- Encryption is spreading and someone must decide the isolation boundary before the next write.
- A file server, hypervisor cluster or backup tier shows mass renames, staging activity or recovery-agent tamper.
- Recovery is proposed and the question "is the entry path actually closed" has no evidenced answer.
- A new segment, subsidiary or cloud account is discovered mid-incident and must be brought into scope quickly.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Encryption advancing across two or more segments | Confirmed - Spread Active | Isolate at segment boundary; capture at least one representative host per role |
| Live credential confirmed in the operator's hands | Confirmed - Identity Exposure | Revoke sessions and rotate credentials before host isolation |
| Staging pattern (first-seen archiver, many-to-few writes) without encryption | Confirmed - Pre-Impact Staging | Freeze egress at the boundary, preserve the staging directory, escalate for exfiltration assessment |
| Bulk write with a matching scheduled job and no new extension | Benign Baseline | Record the job and narrow the exclusion to that job only |
| Host unreachable or its share audit absent | Inconclusive - Unmeasured Segment | Keep in scope; do not count as contained or clean |
| Writes continue after isolation timestamp | Control Gap - Containment Failed | Re-check the boundary; find the path that bypassed it before declaring scope fixed |
| Restored host re-encrypted within hours | Confirmed - Re-entry | Return to containment; the vector is open and recovery is premature |

## Containment and Recovery

1. **Preserve volatile state on a representative host per role before the boundary closes** — running processes, network connections, authenticated sessions and loaded modules. Spreading incidents get a partial capture, and the report must say which hosts were captured and which were skipped.
2. **Sequence identity before network when a credential is confirmed.** Revoking sessions and rotating credentials is reversible in minutes; a host rebuild is reversible in days. Take the reversible action first.
3. **Validate the responder path before isolating a management plane.** Log in through the out-of-band route, record the account used, and only then change the boundary. An isolation that locks responders out turns a contained incident into an unmanaged one.
4. **Enumerate re-entry paths on every host you intend to keep powered.** New local administrators, new remote-support services, new scheduled tasks and modified service binaries are paths isolation does not close. Close them before recovery starts, not after the first re-encryption.
5. **Hand off to recovery only on evidence, not on schedule.** The handoff requires: entry path closed and verified by a failed re-authentication attempt, re-entry paths removed, and staging/exfiltration question answered or explicitly deferred with counsel informed. [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) begins at that point.
