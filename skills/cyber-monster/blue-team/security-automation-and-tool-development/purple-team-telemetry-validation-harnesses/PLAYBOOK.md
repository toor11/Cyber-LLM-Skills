# Operational Triage and Response Playbook

> Sub-skill: [`purple-team-telemetry-validation-harnesses`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a validation-harness incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A technique marked covered produces no telemetry during validation.
- A validation run leaves lab artefacts behind.
- Measured latency far exceeds the expected detection window.
- A published Navigator layer fails to import or shows unexpected scores.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| No event for the correlation id | Collection gap | Check agent config and log source onboarding before rules |
| Event present, no alert | Detection gap | Route to detection engineering with the raw event attached |
| Alert without key fields | Fragile detection | Strengthen the rule or the log configuration |
| Cleanup failed | Unknown lab state | Stop the run, reset the host from baseline, re-validate |
| Layer import failure | Schema error | Emit `versions.layer: "4.5"` with a valid domain and validate |

## Containment and Recovery

1. **Preserve before mutating:** keep the correlation ids, the raw events retrieved, the per-case verdicts, and the layer file. The raw event is the evidence that the case produced telemetry.
2. **Check blast radius:** determine whether the gap affects one technique or a whole log source, and which other validations depended on the same source.
3. **Eradicate the root cause:** fix collection or the rule, re-run the same case with a fresh correlation id, and only then update the coverage layer.
