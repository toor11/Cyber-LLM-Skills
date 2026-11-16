# Detection Queries and Telemetry Artifacts

> Sub-skill: [`security-testing-in-ci-cd`](SKILL.md) | Family: **Application Security**

Pipeline and provenance checks with the evidence each produces. Rows are answerable from workflow files and run history.

## Workflow Input Safety

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Expression interpolation in `run:` | workflow files containing `${{` inside `run:` blocks | Zero; all event data arrives via `env:` |
| Privileged trigger | workflows on `pull_request_target` or `workflow_run` with a checkout of untrusted refs | Zero, or an explicit two-job split with no secrets in the untrusted job |
| Token permissions | `permissions:` block per workflow | Explicit and read-only by default |

## Gate Liveness

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Continue-on-error | scanner steps carrying `continue-on-error: true` | Zero on blocking stages |
| Probe run | runs against a branch with a planted defect | Stage fails; the reason names the intended rule |
| Bypass audit | merges with an override label | Each has an accepted-risk id |

## Provenance

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Image by digest | deploy manifests referencing `:latest` or a mutable tag | Zero |
| Provenance attestation | `.intoto.jsonl` or cosign attestation attached to the release | Present and verified with `slsa-verifier` |
| Action pinning | `uses:` entries with a tag instead of a commit SHA | Zero on jobs with write scope |

## Telemetry Prerequisites

- Repository admin read on branch protection and Actions settings, since enforcement lives there.
- Run history long enough to observe a failure, not only the current YAML.
- The accepted-risk register, so overrides can be distinguished from incidents.

## Deployment Gates

- A blocking stage with no recorded failure in 90 days is re-probed before the next audit, not assumed healthy.
- Any change to `permissions:` or triggers requires the same review as application code.
