# Operational Triage and Response Playbook

> Sub-skill: [`business-email-compromise-response`](SKILL.md) | Family: **Incident Response**

Structured runbook for `business-email-compromise-response`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A counterparty reports a payment-instruction change or an unusual request received from one of your mailboxes.
- Mail-flow telemetry shows external auto-forwarding from a mailbox that had none.
- The mail security layer flags a mailbox rule with an external destination, or a hidden rule is discovered during an unrelated review.
- A user reports missing mail, sent items they did not write, or a password or MFA change they did not make.
- Identity protection raises a risky sign-in or an anomalous token pattern for a principal with mailbox access.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Forwarding or hiding rule plus a sign-in from unfamiliar infrastructure in the same window | Confirmed BEC | Snapshot rules and audit records, disable the rule, revoke sessions and consent grants, then reset the credential |
| Payment already sent to a changed account | Confirmed fraud, active loss | Escalate to bank fraud recall with the wire reference in the first hour; containment proceeds in parallel, not first |
| OAuth consent grant with mail scopes and no matching service-owner record | Control Gap (persistence) | Revoke the grant and its tokens; a password reset alone leaves the actor with a live refresh path |
| Rule with an external destination that predates the sign-in window and matches a documented connector | Benign Baseline | Record the connector identity and add it to the exclusion set; do not touch the rule |
| Impossible-travel alert with a successful MFA challenge and continuous device identity | Benign Baseline (egress change) | Confirm with the user and the VPN egress inventory, then tune the detection to device continuity |
| Mailbox audit not enabled or unified audit log retention shorter than the dwell window | Inconclusive (Telemetry Gap) | State the gap explicitly; reconstruct from mailbox contents and recipient copies rather than asserting a clean timeline |

## Containment and Recovery

1. **Snapshot before state change.** Export rules with `-IncludeHidden`, the audit records for the dwell window, authentication methods and consent grants, and hash the exports. Every later action is then provable against a preserved baseline.
2. **Disable rules before deleting them.** A disabled rule still exists for evidence and stops the exfiltration immediately; deletion destroys the destination address and the rule definition that the disclosure obligation depends on.
3. **Revoke tokens and grants before the credential reset.** Password reset then revocation leaves a window in which the actor's refresh token still works, and resetting first also signals the compromise. The order is consent grant, refresh tokens, MFA method removal, then password.
4. **Verify each revocation on the surface that issued the token.** Cloud, on-premises Exchange, legacy protocol endpoints and third-party filters cache credentials independently; a revocation confirmed in the tenant console is one surface, not the estate.
5. **Enumerate and notify the downstream victims.** Every external recipient of actor-sent messages in the window is a victim of impersonation even if no money moved; produce the list from send events with message ids and hand it to the party that owns the relationship.
6. **Close on evidence, not on sentiment.** The case closes when the rule events, revocation events, method removal and re-enrolment are all present in the audit record, and when the last actor session has expired with no successor. Anything short of that is a monitoring state, not a closure.
