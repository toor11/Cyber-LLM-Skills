# Operational Triage and Response Playbook

> Sub-skill: [`yara-and-yara-x-scanner-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a signature-scan incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- Scan job hits its wall-clock budget or its per-target timeouts.
- A rule starts matching clean-ware in production.
- `yr compile` fails after a rule PR merges.
- A detector that used to alert goes silent after a scanner or ruleset change.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `--profiling` shows one rule above ~50% of scan time | Rule defect | Rewrite atoms or add a cheap structural guard; re-profile before scaling workers |
| Timeouts cluster on a small set of targets | Target shape | Check file size and packing; raise the per-target budget only for that class |
| Clean-ware match with an entropy-only condition | False-positive generator | Add a discriminating structural term and register the clean file as a fixture |
| Compile error in one file, directory scan "clean" | Coverage loss | Restore compile gating in CI; the scan covered fewer rules than assumed |
| `.yarc` older than the newest rule edit | Stale ruleset | Rebuild the compiled artifact from the current tree |

## Containment and Recovery

1. **Preserve before mutating:** snapshot the rule tree hash, the `yr --version` output, the compiled artifact, and the profiling report together — without all four the slowdown is not reproducible.
2. **Check blast radius:** count how many hosts and how many rules share the offending rule before editing; a shared ruleset edit changes fleet behaviour at once.
3. **Eradicate the root cause:** fix the atoms or structural guard, re-run the positive/clean-ware differential, then re-enable alerting at full scope.
