# Detection Signals and Blue-Team Handoff

> Sub-skill: [`python-atheris-and-hypothesis-security-fuzzing`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- CI jobs running Hypothesis with `--hypothesis-show-statistics` on a schedule but not in the default pipeline.
- A committed `.hypothesis/examples` database containing production identifiers, a data-leak risk in the repository.
- Atheris or libFuzzer command lines in a build step that also publishes artefacts.
- Test suites whose duration varies widely between runs, the signature of unbounded example generation.
- New `@example` decorators added with values copied from production data.
- `pytest` processes with high CPU and no output for minutes, matching a shrinking phase.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
