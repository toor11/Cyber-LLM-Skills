# Operational Triage and Response Playbook

> Sub-skill: [`iac-rego-opa-and-checkov-policy-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a policy-gate incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A resource known to violate policy was applied without the gate failing.
- The policy gate blocks a compliant change across many pull requests.
- `opa test` or `conftest test` behaves differently in CI than locally.
- A newly added custom Checkov check produces no findings.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Attribute present in `after_unknown`, gate passed | Fail-open defect | Add the `is_object` tri-state test and an unknown-branch fixture; treat unknown as deny |
| Gate reports violations on destroy-only changes | Over-broad rule | Filter on `actions` and skip pure deletes; add a delete fixture |
| Local pass, CI fail on the same policy | Version skew or wrong input shape | Pin OPA/conftest versions; confirm the fixture is a plan, not source config |
| Custom check absent from results | Discovery failure | Add `__init__.py` and assert the check ID appears in the run output |
| Many violations with one root resource | Shared module/template | Fix the source module rather than excluding each instantiation |

## Containment and Recovery

1. **Preserve before mutating:** keep the `tfplan.json`, the policy revision, and the `opa`/`conftest` versions together; a verdict is not reproducible without all three.
2. **Check blast radius:** determine whether the policy is applied per-repository or organization-wide before editing; a shared policy change alters every pipeline at once.
3. **Eradicate the root cause:** fix the tri-state logic or discovery, extend the fixture set with the failing shape, and confirm the gate now blocks it before re-enabling.
