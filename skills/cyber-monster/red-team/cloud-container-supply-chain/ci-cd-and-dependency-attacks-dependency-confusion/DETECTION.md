# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ci-cd-and-dependency-attacks-dependency-confusion`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Registry egress log: a request for a scoped name to the public registry from a build network, which is the fallback happening.
- Lockfile diff: a new `resolved` URL pointing at the public registry for an internal name.
- Artifact proxy log: a request the proxy forwarded for a name that matches an internal scope.
- Package-manager audit: an install resolving a version higher than the internal registry's latest.
- CI log: a `404` from the internal registry followed by a successful install, which is the fallback in one log sequence.
- Registry publish event: a new package published under an internal-looking scope by an account outside the organisation.
- Build reproducibility metric: two builds of the same commit resolving different dependency trees.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
