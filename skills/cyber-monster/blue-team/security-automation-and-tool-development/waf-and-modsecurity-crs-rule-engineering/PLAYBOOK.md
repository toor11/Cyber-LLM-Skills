# Operational Triage and Response Playbook

> Sub-skill: [`waf-and-modsecurity-crs-rule-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a WAF-tuning incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A legitimate request is blocked with a CRS rule ID in the log.
- A tuning change is deployed and attack traffic is no longer blocked.
- Traffic breaks after a paranoia or threshold change.
- The regression suite fails in CI but passed locally.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| One rule firing on a benign field | False positive | Path-scoped `ruleRemoveTargetById` in the correct phase |
| Rule disabled globally in configuration | Coverage loss | Restore the rule, scope the exclusion, re-run the suite |
| Blocked at low score | Threshold or increments changed | Compare against the previous configuration; restore and re-test |
| Exclusion present but alert continues | Phase mismatch | Move the `ctl` to the phase where the variable exists |
| CI and local results differ | Version or PL drift | Record CRS version and paranoia level per environment |

## Containment and Recovery

1. **Preserve before mutating:** save the current CRS configuration, the audit log excerpt showing the firing rule IDs, and the CRS version. A tuning decision without the original alert is guesswork.
2. **Check blast radius:** determine whether the change affects one virtual host, one path, or the whole WAF; a global change alters protection for every application behind it.
3. **Eradicate the root cause:** apply the scoped exclusion, run the suite including an attack case on the same endpoint, and monitor the excluded endpoint for a week before considering the change settled.
