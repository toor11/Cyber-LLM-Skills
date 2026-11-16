# Detection Signals and Blue-Team Handoff

> Sub-skill: [`terraform-state-and-gitops-argocd-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- S3 access log: `GetObject` on the state prefix by a principal other than the pipeline role.
- Terraform lock table event: two concurrent lock acquisitions on the same key, which is the interleaving signal.
- Argo CD audit: an Application created or synced whose source repository is outside the project's `sourceRepos`.
- Argo CD event: a project token used against `/api/v1/projects/{project}/detailed`, which is the advisory-shaped request.
- Kubernetes audit: creation of a cluster-scoped resource by an Argo CD service account in a project with an empty whitelist.
- Configuration event: a backend block losing `encrypt` or `kms_key_id`, or a project's `sourceRepos` gaining `*`.
- Version event: Argo CD below the patched release for the project-token advisory.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
