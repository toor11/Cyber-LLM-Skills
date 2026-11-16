# Operational Triage and Response Playbook

> Sub-skill: [`phishing-email-and-header-triage-automation`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a phishing-campaign incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A user reports a suspicious message and the SOC queue needs an automated first pass.
- The same subject and attachment hash appear across multiple recipients.
- A message passes authentication but the domain is unexpected.
- An attachment hash matches a known-malicious sample.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Trusted auth result is `fail` with matching authserv-id | Confirmed spoof | Block sender infrastructure, purge matching messages, notify recipients |
| Auth results only untrusted (below boundary) | Inconclusive | Escalate for manual header review; do not clear the message |
| Attachment hash matches known-malicious | Confirmed payload | Purge campaign-wide by hash, isolate hosts that opened it |
| ARC chain present with original auth passing | Legitimate forward | Close as benign with the ARC evidence recorded |
| Lookalike domain above threshold | Likely impersonation | Block domain, check for credential submission, notify brand owner |

## Containment and Recovery

1. **Preserve before mutating:** store the raw message with its SHA-256, the header ordering, and the extracted artefact list; a purge removes the evidence from mailboxes, so copy first.
2. **Check blast radius:** search by subject, sender infrastructure, and attachment hash across all recipients and mailboxes, not just the reporter's.
3. **Eradicate the root cause:** purge the campaign, block the sending infrastructure, and add the observable to the IOC pipeline so the next wave is caught earlier.
