# Detection Signals and Blue-Team Handoff

> Sub-skill: [`python-ast-and-libcst-security-linters`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Python processes running `compileall` or AST dumps over a repository they do not own.
- Custom linter entry points added to pre-commit config without a corresponding test fixture.
- `libcst` rewrites committing whole-file reformat diffs, which hides the semantic change from review.
- Lint rule files loaded from a path outside the repository, a supply-chain risk for every contributor.
- Suppression comments (`# noqa`) added in bulk, indicating a rule was enabled without calibration.
- Interpreter version mismatches between CI and developer machines causing divergent node shapes.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
