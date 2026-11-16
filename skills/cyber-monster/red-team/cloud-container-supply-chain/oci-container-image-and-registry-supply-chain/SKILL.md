---
name: oci-container-image-and-registry-supply-chain
description: Assesses OCI container registries, Cosign/Sigstore image signing, SLSA provenance attestations, multi-stage Dockerfile secret leakage in intermediate layers (`docker history`), and mutable `:latest` tag overwrite risks. Use when auditing container build and registry pipelines.
family: cloud-container-supply-chain
tier: leaf
triggers: ["container image signing", "cosign sigstore", "dockerfile secret layer", "slsa provenance", "oci registry security"]
cwe: [CWE-353, CWE-522]
owasp: []
attack: []
capec: []
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# OCI Container Image and Registry Supply Chain - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Container image supply-chain review has four verifiable links. The image identity: a tag is mutable, so a deployment that references `app:latest` or `app:v1.2` runs whatever the registry holds under that name at pull time, while a digest reference is immutable. The image content: a Dockerfile that copies a build context, runs as root, or installs from an unpinned base is the content problem, and `docker history` plus layer extraction is where it shows. The signature: Sigstore cosign attaches a signature and an attestation to a digest, and verification requires a keyless identity or a public key plus a policy that says which identities are acceptable — a signature that verifies against the wrong identity is worse than no signature because it looks like a control. The registry access: a registry that allows anonymous pull of internal images, or a token with push access that is shared across CI jobs, is the access problem. In 2025 the SBOM and attestation ecosystem matured to the point where the review can require an SBOM per image and check its provenance rather than trusting the Dockerfile, and the CISA guidance on the npm worm applies to container build steps as well: a compromised dependency inside a build is a compromised image.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a deployment references a tag rather than a digest **THEN** the finding is mutability; the fix is a digest reference or an admission policy that resolves tags.
2. **IF** images are signed **THEN** read the verification policy; a signature checked against no identity constraint is not a control.
3. **IF** the registry allows anonymous pull **THEN** the internal image set is enumerable and readable, which is a separate finding from the content.
4. **IF** the Dockerfile copies the whole build context or runs as root **THEN** the content finding is specific and the layer is the evidence.
5. **IF** there is no SBOM or attestation per image **THEN** record the absence; it is the artefact that makes dependency review possible after the fact.
6. **IF** the question is a dependency inside the build rather than the image itself **THEN** start at [`npm-pypi-and-cargo-install-hook-supply-chain`](../npm-pypi-and-cargo-install-hook-supply-chain/SKILL.md).
7. **IF** every deployment is digest-pinned, signature-verified against a named identity, and the registry requires auth **THEN** record `Verified Safe` with the three artefacts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Resolve the reference.** For each deployment, record whether it names a tag or a digest. The digest is the identity; a tag is a lookup.
2. **Verify the signature against a policy.** `cosign verify` with the expected identity and issuer, or the public key. A verification that succeeds without an identity check is the finding.
3. **Read the image content.** Base image and its digest, the user the process runs as, the build context copy, and the layer count. Each is a specific finding or a specific control.
4. **Define the baseline-vs-probe differential.** Baseline: the digest currently deployed and its signature identity. Probe: the digest the tag resolves to now, and whether it is the same digest with the same signature. A different digest under the same tag is the mutability finding, proven without pulling anything.
5. **Name the stop condition.** Stop at the first reference that is mutable, the first signature that verifies without an identity constraint, or the first anonymous-pull success. Do not pull and run an image.
6. **State the proof.** Report the reference, the resolved digest, the signature identity, the registry access result, and the admission policy that would enforce the fix. If all four links hold, record the negative with the digest and identity.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `image: registry/app:1.4` in a deployment | A mutable reference, so the running code can change without a manifest change | Kubernetes manifests, compose files |
| `image: registry/app@sha256:...` | An immutable reference, which is the control | Kubernetes manifests |
| `cosign verify --certificate-identity` with an exact workflow identity | Signature bound to a specific builder, which is a real control | Sigstore cosign |
| `cosign verify` with no identity flags | The signature is checked for validity but not for who made it, which is the finding | Sigstore cosign usage |
| `RUN apt-get install` without a version pin in the Dockerfile | Unpinned package, so the image content is not reproducible | Dockerfile |
| Anonymous `GET /v2/<name>/manifests/<tag>` returning a manifest | The registry permits unauthenticated pull, so internal images are readable | OCI registry API |

## Worked Contrast

**Vulnerable: mutable tag, signature checked without an identity, anonymous pull**

```yaml
# Deployment references a mutable tag, so the running code is whatever the registry
# holds now, and nothing verifies who built it.
spec:
  containers:
    - name: api
      image: registry.example.com/api:1.4
```

```text
# Verification that checks a signature exists but not who made it:
cosign verify registry.example.com/api:1.4
# Anonymous manifest fetch succeeds:
curl -s -o /dev/null -w '%{http_code}\n' https://registry.example.com/v2/api/manifests/1.4
```

**Hardened: digest reference, identity-bound verification, authenticated registry, admission enforcement**

```yaml
# The digest is the identity, and the annotation records which builder signed it.
spec:
  containers:
    - name: api
      image: registry.example.com/api@sha256:5f2a1c9e8b7d6a4f3e2d1c0b9a8f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d
```

```text
# Verification bound to a specific builder identity and issuer:
cosign verify registry.example.com/api@sha256:5f2a1c9e... \
  --certificate-identity "https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Registry requires authentication for pull:
curl -s -o /dev/null -w '%{http_code}\n' https://registry.example.com/v2/api/manifests/1.4   # 401
```

```yaml
# Admission policy refuses unsigned images and tags.
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-digest-and-signature
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        resources: ["pods"]
        operations: ["CREATE"]
  validations:
    - expression: "object.spec.containers.all(c, c.image.contains('@sha256:'))"
      message: "images must be referenced by digest"
```

**Why this matters:** The left deployment can be replaced by anyone with push access, the signature check proves only that some signature exists, and the registry serves manifests anonymously, so the chain from build to run has three independent gaps. The right deployment pins the digest, verifies the signature against one workflow identity and issuer, requires authentication to pull, and enforces digest references at admission so a tag reference cannot be deployed at all.

## When It Is NOT This Issue

- **A tag reference inside a Helm chart template that resolves to a digest via a values file.** The rendered manifest has the digest; check the rendered output rather than the template.
- **A signature verified with a public key held by the organisation rather than a keyless identity.** That is a valid model when the key custody is documented.
- **An anonymous pull on a public base image such as `alpine`.** Public by design; the finding would be an internal image in a public namespace.
- **A Dockerfile that runs as root but drops privileges in the entrypoint before serving.** Check the entrypoint before filing.
- **An SBOM attached as an attestation rather than a separate artifact.** Both are valid; the finding is the absence, not the format.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `oci-container-image-and-registry-supply-chain` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `oci-container-image-and-registry-supply-chain` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: oci-container-image-and-registry-supply-chain
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-353, CWE-522 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `oci-container-image-and-registry-supply-chain` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-353, CWE-522`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
