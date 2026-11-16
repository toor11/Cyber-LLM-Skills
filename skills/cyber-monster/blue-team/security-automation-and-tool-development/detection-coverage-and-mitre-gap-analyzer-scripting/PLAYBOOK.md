# Operational Triage and Response Playbook

> Sub-skill: [`detection-coverage-and-mitre-gap-analyzer-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a coverage-analysis incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A technique marked covered produced no detection during an incident.
- Coverage percentage moves sharply after a rule cleanup.
- A new log source is onboarded and the matrix does not change.
- An auditor challenges a published coverage figure.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Covered technique with only dead-source rules | Content gap | Onboard the source or retire the rule; do not count it |
| Covered parent, uncovered children | Rollup overstatement | Report per-child verdicts; correct the published figure |
| Source listed but not forwarded | Operational gap | Route to the platform owner, not detection engineering |
| Rule exists, field always null | Content/field gap | Fix the normalizer or the rule's field choice |
| Figure not traceable to rules | Reporting defect | Re-emit with per-technique evidence rows |

## Containment and Recovery

1. **Preserve before mutating:** keep the rule repository revision, the inventory snapshot with its timestamp, and the ATT&CK version. A coverage figure is only meaningful against those three.
2. **Check blast radius:** determine how many published reports or dashboards used the defective matrix before correcting them.
3. **Eradicate the root cause:** fix the join or rollup, re-run the analyzer, and re-publish with evidence — and pair the corrected matrix with measured validation for the top techniques.
