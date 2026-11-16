# Detection Signals and Blue-Team Handoff

> Sub-skill: [`npm-pypi-and-cargo-install-hook-supply-chain`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CI log: a lifecycle script's output appearing in the build log, which proves scripts ran.
- Network egress from the runner: a connection to a paste, webhook, or a domain not referenced in the repository.
- npm audit: a publish event for a package whose maintainer token last authenticated from a CI runner.
- Repository audit: a new workflow file created by a bot account, which is the persistence step in the 2025 campaign.
- Environment read: a process during install reading `~/.npmrc`, `~/.aws/credentials`, or a cloud metadata endpoint.
- Registry event: a version published under a package the maintainer did not intend to release.
- Runner audit: a job that installs dependencies and holds a write token, flagged at workflow review.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
