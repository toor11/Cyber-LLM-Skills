# Detection Signals and Blue-Team Handoff

> Sub-skill: [`js-ts-and-treesitter-security-analyzers`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- `tree-sitter` CLI invocations in pre-commit hooks on developer machines, which is expected; flag only server-side use.
- Node processes loading grammar shared objects from a path outside the project's dependency tree.
- ESLint runs with a config file pointing at a rules directory outside the repository.
- New ESLint plugin dependencies added in a lockfile change with no corresponding rule tests.
- Pre-commit hook durations jumping after a rule addition, indicating an unbounded parse over vendored bundles.
- Query files committed under `.lint/` that capture network or credential identifiers, a data-handling concern.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
