# Operational Triage and Response Playbook

> Sub-skill: [`cloud-incident-response`](SKILL.md) | Family: **Incident Response**

Structured runbook for `cloud-incident-response`. Paired offensive/mechanics reference: [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md).

## Triggers

- GuardDuty, Defender for Cloud or Security Command Center raises a credential-access, crypto-mining or anomalous-API finding in a production account.
- Cloud spend jumps without a corresponding workload change, or a new region appears in the billing breakdown.
- A provider abuse notice reports outbound scanning, spam or DDoS from your addresses.
- A developer reports an access key exposed in a repository, a build log or a chat channel.
- An external party reports data that only your object store should hold.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Actor principal calls operations outside its own ninety-day set from an unfamiliar address, with a trust-policy edit in the same window | Confirmed compromise | Preserve the trail and identity logs, enumerate persistence objects, revoke the credential and any assumed-role sessions, then rebuild trust |
| `StopLogging` or `DeleteTrail` followed by other activity | Confirmed defense impairment plus unknown scope | Restart logging immediately, treat the gap as unreconstructable, and pivot to resource-side evidence such as bucket access logs and platform job history |
| Object reads on a sensitive prefix by an undocumented principal with high object breadth | Confirmed data access | Quantify the object set from data events, engage the data-owner for disclosure scope, and revoke the reading principal |
| API error burst with `Throttling` or `ServiceUnavailable` and no successful state change | Provider event, not intrusion | Confirm against the provider status feed, record the reference, and stop incident procedure |
| New keys or users created but every one attributable to the joiner list or the pipeline inventory | Benign Baseline (automation) | Add the principals to the documented baseline and tune the rule to principal age and attribution |
| Data-event tables empty across the whole window | Inconclusive (Data-Event Gap) | State that read scope cannot be established from logs; preserve bucket-level and network-level substitutes before asserting any scope |

## Containment and Recovery

1. **Preserve the audit record before touching the estate.** Export the management-event window and the identity-provider sign-in records to storage outside the compromised account, with hashes. An actor with `DeleteTrail` or bucket-delete rights can remove the evidence while the responder works.
2. **Sequence revocation by credential type.** Long-lived key: deactivate, then delete after the window closes. Assumed-role session: attach a session-revocation policy keyed to token issue time. Federated or workload identity: revoke at the issuer, because the cloud provider never held the credential. Doing these in the wrong order leaves a live path while appearing contained.
3. **Stage authority before removing it.** Confirm the responder's own principal does not depend on a role being revoked, and that the break-glass path is reachable and tested. Lockout recovery during an incident is slower than the containment it was meant to accelerate.
4. **Enumerate persistence as an inventory, not a hunt.** Keys, users, roles, trust policies, identity-provider entries, OAuth grants and function triggers created inside the window each get an owner and a disposition. Anything unattributed is removed; anything attributed is documented and kept.
5. **Prove each step took effect.** A revocation is proven by a later denial or by the absence of successful calls from that principal after the timestamp. A snapshot is proven by a completed job and a readable copy in a separately controlled account.
6. **Close on declared scope, not on silence.** The case ends with a written statement of what was established about data access, what was not, and why — including the exact logging gap that prevents a stronger claim. An unqualified "no data accessed" from a window without data events is the failure mode to avoid.
