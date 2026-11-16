# Detection Signals and Blue-Team Handoff

> Sub-skill: [`github-actions-and-oidc-federation-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: `sts:AssumeRoleWithWebIdentity` where `requestParameters` shows a subject claim outside the approved repository set.
- CloudTrail field: `userIdentity.sessionContext.webIdFederationData` naming a repository or ref not in the approved list.
- Workflow audit: a run from a fork or an unexpected repository that requests an OIDC token.
- IAM configuration event: a role trust policy change adding a wildcard subject or removing the `aud` condition.
- GitHub audit log: creation of a new repository in the organisation, which widens a wildcard subject immediately.
- CloudTrail correlation: an OIDC assumption followed by actions outside the deploy pipeline's normal set.
- Configuration drift: a workflow moving `id-token: write` from a job to the top level.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
