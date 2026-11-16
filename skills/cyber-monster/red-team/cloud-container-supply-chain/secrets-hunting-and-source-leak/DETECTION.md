# Detection Signals and Blue-Team Handoff

> Sub-skill: [`secrets-hunting-and-source-leak`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- GitHub audit event: a secret-scanning alert opened, with the provider and whether it is `publicly_leaked`.
- CI log: a masked value rendered unmasked, which the platform logs as a masking failure.
- Git event: a commit that adds a file matching `.env`, `id_rsa`, or a credential extension.
- Container registry event: an image pushed whose layers contain a credential path, checked at admission.
- Provider audit: a credential used from an IP or ASN that has never used it before, which is the post-leak use signal.
- Secret-manager event: a rotation for a credential whose last-use timestamp does not match the rotation schedule.
- Dependency install audit: a postinstall script reading `~/.npmrc` or an environment variable matching a cloud credential name.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
