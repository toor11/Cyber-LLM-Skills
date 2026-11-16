# Operational Triage and Response Playbook

> Sub-skill: [`sigma-pipeline-and-backend-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a detection-as-code compiler failure. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- CI job `sigma check` or the compile stage turns red on a rule-only change.
- A detection that used to fire goes silent after a pipeline or backend upgrade.
- `sigma convert -t <target>` fails with a modifier or transformation error.
- A golden-file diff appears across many rules with no rule-content change.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `collection.errors` names one file and one modifier | Rule defect | Fix the rule's modifier or logsource; re-run `sigma check` |
| Compiled query contains a doubled field path (`process.process.*`) | Duplicate mapping | Remove the redundant `ProcessingItem` or the backend pipeline, not both |
| Golden diff touches every rule after a dependency bump | Compiler drift | Pin `pysigma` and backend versions; update goldens in an isolated commit |
| `sigma list targets` lacks the expected backend | Environment | `sigma plugin install <backend>` in the same env as `sigma-cli` |
| Rule compiles, matches nothing, logsource category absent from inventory | Telemetry gap | Open a log-onboarding action; do not edit the rule to compensate |

## Containment and Recovery

1. **Preserve before mutating:** keep the failing compiled query, the rule YAML, and the pySigma/backend versions together as the incident record; that triple is the only reproducible artifact.
2. **Check the blast radius:** count how many deployed rules share the changed pipeline item before reverting anything; a pipeline revert is fleet-wide.
3. **Eradicate the root cause:** fix the pipeline item or rule modifier, re-run the fixture differential, and only then restore the previous detection coverage.
