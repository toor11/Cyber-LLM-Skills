# Detection Signals and Blue-Team Handoff

> Sub-skill: [`infrastructure-as-code-review`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Pipeline event: a `terraform apply` without a preceding policy-gate step in the same run.
- Plan artefact: a `delete`/`create` action on a resource tagged as holding data, flagged at review of the stored plan.
- Drift alert: `terraform plan -detailed-exitcode` returning 2 on a scheduled run, which means the estate differs from the code.
- Repository event: a `.tf` change to a security-relevant property without a corresponding policy test update.
- State audit: a resource present in state with no code reference, which indicates an out-of-band change.
- Provider audit: a resource created by a principal other than the pipeline's role.
- Policy engine log: a `conftest` or OPA denial that was overridden with an exception, which is where gates erode.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
