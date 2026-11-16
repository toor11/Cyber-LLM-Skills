# Detection Signals and Blue-Team Handoff

> Sub-skill: [`supply-chain-attack-recon`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Registry audit: a publish from an IP or token that has not published before, or outside the package's cadence.
- Registry audit: a maintainer added to a package, which is a rare and high-signal event.
- Repository audit: a workflow file modified to reference a new secret name or a new registry.
- Publish event: a version whose provenance attestation is missing while previous versions had one.
- Dependency diff: a new transitive dependency introduced in a patch release.
- Account event: MFA disabled or changed on a registry account holding publish rights.
- Certificate transparency: a new certificate for a registry or artefact hostname under an estate domain.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
