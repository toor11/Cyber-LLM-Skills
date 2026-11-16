# Operational Triage and Response Playbook

> Sub-skill: [`threat-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Structured runbook for `threat-hunting`. Paired offensive/mechanics reference: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `threat hunting`.
- Alert, hunt outlier, or review request matching `hunt hypothesis`.
- Alert, hunt outlier, or review request matching `proactive hunting`.
- Alert, hunt outlier, or review request matching `hunting methodology`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Probe hits on baseline-clean hosts | Detection candidate | Convert to a rule, verify against a benign replay, then enable in alert-only mode |
| Hits only on hosts already known to use NTLM | Baseline artefact | Extend the baseline list instead of raising a finding |
| No hits and incomplete coverage | Unanswerable | Record the telemetry gap with the missing event or field and open a coverage ticket |

## Containment and Recovery

1. **Preserve the query and the window** before closing: a hunt result that cannot be re-run is an anecdote.
2. **Confirm on the endpoint** when central telemetry is ambiguous; process ancestry and service creation settle most sequence questions.
3. **Convert before you forget:** a positive hunt has a short half-life, and the rule is the only durable output.
