# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ci-cd-and-dependency-attacks-pipeline-injection`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Workflow log: a command in the log that the workflow author did not write, which is the direct evidence of execution.
- Workflow audit: a run from a fork whose log contains shell metacharacters in an echoed value.
- Runner process event: a child process of the step shell whose command line does not appear in the workflow file.
- Network egress from the runner: a connection to an endpoint not referenced in the workflow, which is the exfiltration step.
- Secret-access log: a secret read by a workflow triggered from a fork, which should be impossible.
- Code-scanning rule: `${{ github.event.` inside a `run:` block.
- Configuration event: a workflow change that moves an expression from `env:` into `run:`.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
