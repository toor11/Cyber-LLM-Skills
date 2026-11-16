# Operational Triage and Response Playbook

> Sub-skill: [`cis-benchmark-and-baseline-compliance-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a compliance-audit incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- An external assessment finds a failed control that the internal audit marked compliant.
- A drift report shows a control changing every run.
- The audit produces a large block of `not_applicable` results after an OS upgrade.
- Remediation is requested and the audit must prove the fix.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| File says compliant, runtime says otherwise | Wrong observation method | Re-check with the effective-value query and fix the control |
| Unreadable check marked pass | Tri-state defect | Convert to `error`/`not_applicable`, add a regression test |
| Mass `not_applicable` after an upgrade | Benchmark version mismatch | Re-map the control table to the new revision |
| Control flips every run | External churn | Identify the automating task; the audit is correct |
| Audit changed host state | Read-only violation | Remove the mutating command and re-baseline |

## Containment and Recovery

1. **Preserve before mutating:** keep the result set, the benchmark version, the control table revision, and the command used per control. A compliance claim without these is not reproducible.
2. **Check blast radius:** determine how many hosts and reports are affected by the defective control before re-running anything, since a re-run overwrites the baseline.
3. **Eradicate the root cause:** fix the observation method or mapping, re-audit the affected hosts, and re-issue the report with corrected findings and the new baseline.
