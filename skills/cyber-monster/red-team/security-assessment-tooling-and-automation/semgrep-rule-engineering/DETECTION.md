# Detection Signals and Blue-Team Handoff

> Sub-skill: [`semgrep-rule-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Semgrep runs in CI with `--config auto` against a private repository, which sends code paths to a remote registry.
- `semgrep --test` failures surfaced as build errors without a rule change, indicating a floating ruleset.
- Rule files added under `.semgrep/` that disable project rules via `--exclude-rule`.
- Semgrep registry fetches from a build agent whose egress policy should block them.
- Scan output files containing source snippets written to a shared artefact path.
- Sudden finding-count drops after a `paths:` edit, which usually means the rule stopped covering the target directory.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
