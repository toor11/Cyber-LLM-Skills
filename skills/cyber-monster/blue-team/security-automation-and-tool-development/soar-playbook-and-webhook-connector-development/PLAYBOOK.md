# Operational Triage and Response Playbook

> Sub-skill: [`soar-playbook-and-webhook-connector-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an automation-incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A host or account was contained without an analyst decision.
- The same containment appears twice for one entity.
- A containment action reported failure during a mass-alert event.
- A webhook endpoint received traffic from an unexpected source.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Protected asset contained | Policy gap | Release containment, add the asset class to the refusal list, add a fixture |
| Duplicate containment | Missing idempotency | Add keyed dedup before the outbound call; reconcile the audit log |
| Mass containment "failures" during throttling | No backoff | Add bounded retry with jitter; re-run for the failed entities |
| Unsigned or skewed request accepted | Authentication gap | Enable HMAC over raw body plus skew window; rotate the secret |
| Action executed without an approver record | Gate gap | Treat as a control failure; add the action to the gated list |

## Containment and Recovery

1. **Preserve before mutating:** keep the raw request body, signature header, timestamp, decision record, and the vendor's action log. The request body is the only proof of what was asked.
2. **Check blast radius:** enumerate every entity the playbook acted on since the defect was introduced, and confirm the reversal path works for each before reversing in bulk.
3. **Eradicate the root cause:** fix the gate, dedup, or backoff, replay the fixture set including the protected-asset and duplicate cases, and only then re-enable automation.
