# Operational Triage and Response Playbook

> Sub-skill: [`ole-pdf-and-office-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a malicious-document incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A user reports a document that asked them to enable content.
- A mail gateway flags a macro-enabled attachment.
- A document hash matches a known lure.
- A PDF triggers a reader warning on open.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Auto-exec macro plus external target | Confirmed lure | Block the document hash, purge from mailboxes, check who opened it |
| Macros present, no auto-exec and no external target | Suspicious, lower priority | Extract and review code; look for user-click triggers |
| External template target, no macros in the file itself | Confirmed lure pattern | Block the URL at egress/DNS, purge, check proxy logs for contacts |
| PDF with reachable `/JS` from `/OpenAction` | Confirmed active content | Block hash, purge, verify reader version |
| Unreadable macro stream | Inconclusive | Do not close as clean; escalate for deeper parsing |

## Containment and Recovery

1. **Preserve before mutating:** hash and copy the document, record the extraction output, and keep the defanged URL list; purging mailboxes removes the samples.
2. **Check blast radius:** search by hash, by sender infrastructure, and by external target URL across mailboxes and proxy logs.
3. **Eradicate the root cause:** block the hash and the URL, purge, and add the construct pattern to the detection set so the next variant is caught at delivery.
