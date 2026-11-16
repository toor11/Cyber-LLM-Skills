# Operational Triage and Response Playbook

> Sub-skill: [`saas-workspace-and-entra-unified-audit-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `saas-workspace-and-entra-unified-audit-forensics`. Paired offensive/mechanics reference: [`azure-and-entra-attacks`](../../../red-team/cloud-container-supply-chain/azure-and-entra-attacks/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `unified audit log forensics`.
- Alert, hunt outlier, or review request matching `mailitemsaccessed`.
- Alert, hunt outlier, or review request matching `google workspace token audit`.
- Alert, hunt outlier, or review request matching `entra signin forensics`.
- A user reports unexpected sent mail or a consent prompt, indicating a possible BEC or illicit consent grant.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| One `SessionId` spanning an interactive sign-in and workload operations from a network outside the user's normal set, inside the token validity window | Confirmed Token Replay (AiTM) | Revoke sessions and refresh tokens, then rotate credentials; scope every operation in that session before closing |
| `Consent to application.` with delegated permissions and the same `SessionId` appearing in workload audit records | Confirmed Illicit Consent | Revoke the grant and its tokens, then enumerate what the session touched across Exchange, SharePoint and Teams |
| `New-InboxRule` with `ForwardTo` or `RedirectTo`, correlated to a suspect session | Confirmed Mailbox Persistence | Remove the rule, capture its parameters as evidence, and check the destination for received mail |
| Empty `MailItemsAccessed` for a non-E5 mailbox older than 180 days | Inconclusive (Retention Boundary) | State the boundary and pivot to endpoint or proxy evidence inside the same window |
| Session ID with two client origins that both belong to the user's known corporate egress | Benign Baseline | Record the egress pair in the baseline note; do not treat origin variation alone as replay |

## Containment and Recovery

1. **Preserve before mutating:** export the raw `AuditData` JSON for the whole window and the full session pivot before revoking anything, because revocation changes what subsequent queries can attribute.
2. **Revoke sessions, not just passwords:** refresh tokens survive a password reset. Revoke sessions and invalidate refresh tokens, then confirm the old `SessionId` produces no new workload activity.
3. **Enumerate tenant-side persistence:** inbox rules, mailbox forwarding, delegation, consent grants and app registrations are the durable footholds. A clean sign-in history after revocation proves nothing if a forwarding rule remains.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval, and never revoke a break-glass account without a documented replacement path.
