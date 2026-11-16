# Operational Triage and Response Playbook

> Sub-skill: [`email-security-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `email-security-monitoring`. Paired offensive/mechanics reference: [`initial-access-via-phishing`](../../../red-team/network-ad-and-endpoint/initial-access-via-phishing/SKILL.md).

## Triggers

- A user reports a message, or a gateway rule fires on an authentication failure involving an owned domain.
- An executive or supplier display name appears with an unexpected `From` domain.
- A mailbox begins sending to external recipients it has never contacted.
- An inbox rule, forwarding setting, or mailbox permission is created for an account outside a known change.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| DMARC fails with alignment on an owned domain, message delivered because policy is `p=none` | Confirmed Malicious / Gap | Scope the delivery recipients, purge within the approved process, raise the DMARC policy with the owner, and preserve one message as evidence |
| External `From` domain close to an owned one with a matching internal display name and no prior contact | Confirmed Malicious (Impersonation) | Block the sender domain, notify the impersonated person, and check whether any recipient replied or acted |
| Fully authenticated message from an internal account with a new external recipient and a payment-themed subject | Confirmed Malicious (Account Compromise) | Preserve mailbox audit, disable forwarding rules, reset credentials and revoke sessions, then notify recipients |
| Inbox rule created by a service account through an application identity | Benign Baseline (Automation) | Record the application and the rule purpose; exclude by actor identity rather than by rule name |
| Outbound domain count high because of a campaign or migration with a change record | Benign Baseline (Bulk Send) | Attach the change record, keep the behavioural rule for accounts without one |
| Header chain rewritten by the gateway so the original edge hop is unavailable | Inconclusive (Header Gap) | Record which hop is missing, and pivot to the gateway's own connection log for the client address |
| Mailbox audit not retained for the window under investigation | Inconclusive (Retention Gap) | State the retention boundary and open an audit-retention action; do not close the account as clean |

## Containment and Recovery

1. **Preserve before mutating:** save the original message with full headers, the authentication results, the redirect chain, and the mailbox audit export; purging first destroys the artifact set.
2. **Scope before blocking:** count recipients and internal senders for the sender domain before a tenant-wide block, and prefer a transport rule scoped to the observed pattern over a permanent domain ban.
3. **Contain the mailbox, not just the message:** for a compromise, revoke sessions and reset credentials, then remove forwarding and rule artifacts, and only then purge the sent messages.
4. **Close the policy gap that allowed delivery:** a delivered forgery under `p=none` is a policy finding; raise the policy, publish the enforcement date, and monitor aggregate reports before and after.
