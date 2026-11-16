# Detection Signals and Blue-Team Handoff

> Sub-skill: [`go-fuzz-and-cargo-fuzz-harness-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- CI job logs containing `-fuzztime` or `cargo fuzz run` outside a scheduled fuzz workflow.
- `testdata/fuzz/` or `fuzz/corpus/` directories appearing in a pull request diff, which stages crasher inputs into the repository.
- Long-lived `go test` processes at 100% CPU on a build agent with no test result output.
- Artefact uploads named `crash-*` or `leak-*` from a fuzz step, indicating an unpatched finding.
- `go test` invocations with `-fuzz` against a package that has network imports, a sign the harness is not pure.
- Nightly toolchain installs on CI runners that otherwise build with the stable channel.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
