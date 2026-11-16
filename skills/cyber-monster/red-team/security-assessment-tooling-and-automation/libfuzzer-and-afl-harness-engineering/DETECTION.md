# Detection Signals and Blue-Team Handoff

> Sub-skill: [`libfuzzer-and-afl-harness-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Build commands containing `-fsanitize=fuzzer` in a production CI job, which links the fuzzing engine into a shipped artefact.
- `afl-*` binaries or corpus directories committed to a repository's `test/` path.
- Crash artefacts (`crash-*`, `id:*`) uploaded from a CI step, indicating an unpatched finding or a corpus defect.
- Processes with `AFL_` environment variables set on a host that is not a fuzzing worker.
- Sustained 100% CPU with high fork rates on a build agent, matching a corpus minimisation run.
- `__sanitizer_cov_*` symbols present in a released binary, which reveals instrumentation shipped to customers.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
