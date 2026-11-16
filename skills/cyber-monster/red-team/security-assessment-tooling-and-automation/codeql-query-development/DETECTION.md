# Detection Signals and Blue-Team Handoff

> Sub-skill: [`codeql-query-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- CI job logs showing `codeql database create` against a repository with no security workflow.
- Process start of `codeql` with `--source-root` pointing at a checkout outside the build workspace.
- SARIF artefacts written to a workspace path that is not the CI artefact directory.
- Large database directories (`db-*`) appearing on a build agent after a failed scan, indicating a partial extraction.
- Network egress to the CodeQL pack registry from a build agent that normally fetches from an internal mirror.
- GitHub Advanced Security disabled events correlated with a local CodeQL run against the same repository.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
