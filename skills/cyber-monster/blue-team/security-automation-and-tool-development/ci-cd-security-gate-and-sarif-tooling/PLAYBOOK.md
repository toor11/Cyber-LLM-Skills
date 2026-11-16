# Operational Triage and Response Playbook

> Sub-skill: [`ci-cd-security-gate-and-sarif-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a PR-gate incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- The security job blocks a PR that touches no scannable code.
- A known issue stops being reported after a waiver edit.
- Duplicate annotations appear for the same finding across runs.
- A merge proceeds while the security job is red.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Blocked PR with a doc-only diff | Base ref wrong or unavailable | Fetch the explicit base ref, log the resolved SHA, re-run |
| Finding suppressed with no `expires_at` | Permanent bypass | Add an expiry or remove the waiver; fail the job on missing expiry |
| Same finding annotated twice | Missing fingerprints | Generate fingerprints at scan time; do not suppress the duplicate |
| Security job skipped on the merge path | Required-check configuration | Make the gate a required check and verify branch protection |
| Gate exit `2` on a green scanner | Input contract | Inspect the SARIF `runs` array; an empty array means the scan produced nothing |

## Containment and Recovery

1. **Preserve before mutating:** keep the SARIF files, the resolved base SHA, and the gate revision with the job log; a verdict is only reproducible with all three.
2. **Check blast radius:** determine whether the gate is shared across repositories before editing policy thresholds; a shared action changes every pipeline's pass/fail line at once.
3. **Eradicate the root cause:** fix the diff base, fingerprint generation, or waiver schema, then verify the four fixture cases (new-on-changed, old-on-unchanged, live waiver, expired waiver) still produce the intended exit codes.
