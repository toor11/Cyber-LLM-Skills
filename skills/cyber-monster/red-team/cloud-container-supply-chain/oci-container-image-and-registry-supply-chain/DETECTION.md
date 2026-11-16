# Detection Signals and Blue-Team Handoff

> Sub-skill: [`oci-container-image-and-registry-supply-chain`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Admission audit: a pod created whose image reference lacks a digest, when a policy requires one.
- Registry access log: an anonymous manifest request for an internal repository.
- Cosign or policy-controller log: a verification failure naming an unexpected certificate identity.
- Deployment event: a running pod's image digest differs from the digest recorded at admission, which is the mutable-tag replacement.
- Build audit: an image built without an SBOM attestation attached.
- Registry audit: a push to a production repository from a token whose last use was a non-release workflow.
- Vulnerability scanner: a new critical finding in a deployed digest, which triggers the rebuild and re-sign cycle.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
