# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sarif-and-assessment-report-automation`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- SARIF uploads to a code-scanning endpoint from a repository with no configured pipeline.
- Merged reports whose rule ids lack a tool prefix, indicating a normaliser that discards provenance.
- Fingerprint churn across consecutive runs of unchanged code, visible as a fully rewritten result set.
- Report files written to world-readable storage paths that contain exploit detail.
- SARIF generation steps running outside the build container, on hosts without the scanners installed.
- Result counts dropping to zero after a normaliser change, which usually means a parsing regression rather than a fix.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
