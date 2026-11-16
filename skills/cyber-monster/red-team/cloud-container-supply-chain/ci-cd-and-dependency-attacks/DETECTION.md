# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ci-cd-and-dependency-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Workflow-run audit: a `pull_request_target` run whose head repository differs from the base repository.
- Secret-access log: a secret read from a workflow triggered by a fork PR, which should be impossible.
- Runner audit: a self-hosted runner executing a job from a fork, which is the persistent-state risk.
- Registry event: a package publish from a token whose last use was in CI, which is the compromised-token shape.
- Network egress from the runner: connections to a paste or webhook endpoint, which is the exfiltration step in a dependency compromise.
- Dependency diff: a lockfile change that adds a new direct dependency, reviewed as a security event rather than routine.
- Configuration event: a workflow's `permissions` changed from a scoped block to default or `write-all`.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
