# Detection Queries and Telemetry Artifacts

> Sub-skill: [`dependency-and-package-risk-review`](SKILL.md) | Family: **Application Security**

Supply-chain checks with the artefact each produces. Every row is answerable from the build, not from the manifest alone.

## Inventory Fidelity

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| SBOM presence | CycloneDX or SPDX document attached to the image or release | Present, versioned with the artefact, covering transitive packages |
| Lockfile integrity | lock entries carrying `integrity` or `hashes` | All entries; a missing hash means the resolver can supply other bytes |
| Registry pinning | resolved URLs pointing at the public registry from an internal build | Internal mirror or a documented allowlist |

## Advisory Disposition

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Known-exploited match | asset inventory joined against the CISA KEV catalog | Every KEV match has an owner and a remediation date inside the risk tier |
| EPSS triage | EPSS score and percentile for non-KEV advisories | Scores used to order work, never as the sole justification to defer a KEV item |
| Reachability note | advisory records with a reachability statement | Present for every deferred finding |

## Provenance

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Attestation verification | `slsa-verifier verify-image` against the deployed digest | Exit zero, builder identity matches the release workflow |
| Build isolation | workflow using `pull_request_target` or an untrusted checkout | Zero on publishing workflows |
| Install hooks | packages with `preinstall`/`postinstall` in the locked graph | Reviewed list; unexpected hooks are a finding |

## Telemetry Prerequisites

- The built image or release artefact with its digest, so verification targets what runs.
- A resolver that honours the lockfile (`npm ci`, `pip install --require-hashes`, `cargo --locked`).
- The KEV and EPSS feeds available to the pipeline, with a recorded fetch date so the disposition is reproducible.

## Deployment Gates

- No artefact deploys without a verified provenance attestation and a matching SBOM digest.
- Every deferred advisory carries a reachability statement and an expiry, enforced by the same gate that blocks the deploy.
