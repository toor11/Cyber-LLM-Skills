# Detection Signals and Blue-Team Handoff

> Sub-skill: [`go-ssa-and-rust-clippy-security-lints`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Build logs invoking `go vet -vettool` with a binary path outside the module, indicating an unversioned analyzer.
- `analysistest` fixture writes during a build, which means test data is being generated rather than reviewed.
- Compiler flags adding `--extern` dynamic lint libraries in a production build script.
- `cargo dylint` invocations referencing a lint crate from a path outside the workspace.
- New `// want` annotations appearing in a diff without a corresponding rule change.
- Analyzer binaries committed into a repository's `bin/` directory, a supply-chain risk for every developer who builds there.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
