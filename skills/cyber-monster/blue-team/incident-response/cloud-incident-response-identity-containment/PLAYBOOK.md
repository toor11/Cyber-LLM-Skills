# Operational Triage and Response Playbook

> Sub-skill: [`cloud-incident-response-identity-containment`](SKILL.md) | Family: **Incident Response**

Structured runbook for `cloud-incident-response-identity-containment`. Paired offensive/mechanics reference: [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md).

## Triggers

- A cloud access key, client secret or workload token is confirmed leaked in a repository, build log or public post.
- GuardDuty or Defender for Cloud reports anomalous credential use, credential exfiltration or an unusual role assumption.
- Spend, region or API anomalies trace to a single principal or role.
- An identity provider raises a risky sign-in for a principal that holds cloud entitlements.
- A third party reports credentials for your tenant or account appearing in a credential dump.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Unattributed artifact created inside the window plus the actor's session key in the creation record | Confirmed compromise with persistence | Deactivate every key on the principal, attach a token-issue-time deny to the role, revert trust edits, then verify denial |
| Trust-policy edit adding an external principal in the same window | Confirmed re-entry path | Revert the policy before key revocation, otherwise the actor mints a fresh key immediately |
| Token issued by an external IdP or CI system, cloud-side records show only the session | Control Gap (issuer path) | Revoke at the issuer; cloud-side revocation cannot invalidate a token it never minted |
| Multiple concurrent sessions under one role during a deployment window | Benign Baseline (pipeline fan-out) | Correlate with pipeline run ids and stop; do not revoke a role serving a live deployment |
| Old key still active from an integration nobody owns | Baseline (unowned workload) | Attribute the owner, schedule retirement, and do not treat it as actor persistence |
| Session identifiers absent from audit records, so sessions cannot be separated | Inconclusive (Telemetry Gap) | State that session-level containment cannot be verified, and revoke broadly while declaring the collateral |

## Containment and Recovery

1. **Inventory before mutating.** Enumerate keys with creation and last-use times, concurrent sessions with their session keys, consent grants, workload-identity bindings and trust relationships. Store the inventory with a hash; it is both the work list and the record of the state containment started from.
2. **Revert re-entry paths first.** A trust-policy addition, a new identity provider or a new consent grant mints fresh credentials on demand. Revoking keys while a minting path remains produces a loop that looks like the actor is uncontainable.
3. **Revoke per artifact class, and record which primitive hit which artifact.** Key deactivation, role-session deny to token issue time, consent-grant removal, and issuer-side token revocation are four different actions with four different proof obligations.
4. **Preserve a control path.** Confirm before the first containment call that the responder's identity, the break-glass account and the out-of-band management route are all reachable. A lockout during an incident costs the hours that containment was meant to save.
5. **Verify by audit event, then by effect.** Each revocation needs its audit record naming the artifact, followed by a denial or an absence of success from that artifact after the timestamp, with the propagation bound stated.
6. **Publish the residual risk.** Any artifact left attributable-but-unrevoked, any token held by an issuer you cannot reach, and any workload whose role now denies sessions before the cutoff — each is a named residual with an owner and a date, not a footnote.
