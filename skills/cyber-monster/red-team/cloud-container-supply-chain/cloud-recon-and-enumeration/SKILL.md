---
name: cloud-recon-and-enumeration
description: "Maps a cloud footprint from outside and inside: tenant and account discovery, DNS and certificate correlation, public storage enumeration and service fingerprinting. Use at the start of a cloud assessment."
family: cloud-container-supply-chain
tier: core
triggers: ["cloud recon", "cloud enumeration", "cloud footprint", "tenant discovery", "public bucket enum"]
cwe: [CWE-269]
owasp: []
attack: []
capec: [CAPEC-116]
related: [aws-attacks, azure-and-entra-attacks, gcp-attacks, cloud-iam-privilege-escalation]
---

# Cloud Recon and Enumeration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Cloud reconnaissance in an authorised assessment is the mapping of identity, resource, and tenancy boundaries using only read APIs and public metadata. Four channels carry almost everything. The identity channel: `sts:GetCallerIdentity` (or the GCP/Azure equivalents) names the principal, the account, and the partition, which fixes the scope of everything else. The resource channel: `Describe`/`List` calls enumerate what exists, and the errors are informative — an `AccessDenied` on one resource and success on another maps the permission boundary exactly. The public-metadata channel: DNS records, certificate transparency logs, and object-store naming conventions reveal tenant names and cloud providers without any authenticated call. The error-channel channel: a bucket or function URL that returns `NoSuchBucket` versus `AccessDenied` reveals existence without authorisation, which is the enumeration primitive that needs no credentials at all. The review question is what an attacker who holds a low-privilege credential, or none, can learn about the estate — and the answer is usually the full resource inventory plus the organisation's naming conventions, which is enough to target the rest.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you hold any credential **THEN** start with `GetCallerIdentity`; the principal and account fix the scope of every later call.
2. **IF** you have no credential **THEN** the branch is public metadata: DNS, certificate transparency, and object-store name guessing.
3. **IF** the goal is the permission boundary **THEN** use the differential method: one allowed call and one denied call against the same resource type map the boundary precisely.
4. **IF** the target is Kubernetes rather than a cloud API **THEN** switch to [`kubernetes-pentesting`](../kubernetes-pentesting/SKILL.md).
5. **IF** the goal is lateral movement rather than mapping **THEN** start at [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md).
6. **IF** the estate spans several providers **THEN** record the provider per resource; the same hostname can front three different control planes.
7. **IF** every read call in scope is denied and no public metadata identifies a tenant **THEN** record the negative with the calls you made and their error codes.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the identity and the scope.** One call establishes principal, account, and partition. Everything after that is relative to these three facts.
2. **Enumerate in breadth-first order.** Services that reveal the most with the fewest calls: storage, compute, identity, and the organisation structure. Depth-first enumeration burns rate limits for little gain.
3. **Use the error differential deliberately.** For each resource class, record one `allowed` and one `denied` response. The pair bounds the permission set more precisely than a full enumeration.
4. **Choose the branch.** Credentialed API enumeration, public metadata, error-channel existence probing, or cross-account trust discovery.
5. **Name the stop condition.** Stop when the resource inventory, the trust relationships, and the permission boundary are recorded. Do not attempt to read data; existence and metadata are the deliverable.
6. **State the proof.** Report the calls, the resources they returned, the error pairs that bound the permissions, and the public artefacts that named the tenant. If a channel is closed, record it with the response that closed it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `sts:GetCallerIdentity` returning an assumed-role ARN | Which role the credential maps to, and therefore which account's resources are in scope | AWS CLI, any SDK |
| `AccessDenied` on `s3:ListAllMyBuckets` but success on `s3:GetBucketLocation` | The permission boundary excludes account-wide listing while allowing per-bucket metadata | IAM policy boundaries |
| `NoSuchBucket` versus `AccessDenied` on a guessed name | Existence without authorisation, which is the error-channel enumeration primitive | Any object store with per-request errors |
| A certificate transparency entry for `*.internal.example.com` | Internal hostnames and their issuing CA, without any authenticated call | crt.sh, CT logs |
| An `AssumeRole` trust policy naming a wildcard principal | A cross-account edge in the trust graph, discoverable from the policy rather than by trying it | Role trust policies |
| A resource naming convention visible in public DNS | The tenant naming scheme, which makes guessing feasible for the rest | DNS, bucket names, function URLs |

## Worked Contrast

**Vulnerable: enumeration surface left open by error differentiation and public naming**

```python
# One request per candidate name. 403 means the bucket exists, 404 means it does not,
# so the code below maps the estate without any credential.
import urllib.request, urllib.error

def exists(bucket: str) -> str:
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        urllib.request.urlopen(url, timeout=3)
        return "public"
    except urllib.error.HTTPError as e:
        return "exists" if e.code == 403 else "absent"

for tenant in ("acme-prod", "acme-staging", "acme-backups", "acme-logs"):
    print(tenant, exists(tenant))
```

**Hardened: uniform error responses and no tenant-identifying public names**

```text
# Object-store access points resolve to a single distribution hostname, every
# failure returns the same 404 shape, and bucket names carry no tenant identifier.
GET https://data.acme.example/assets/logo.png      -> 404 (uniform body, same as a missing tenant)
GET https://data.acme.example/unknown/x            -> 404 (identical body and headers)

# Bucket names are account-scoped and opaque:
acme-data-8f21c4e9  (no environment, no team, no customer name)
```

**Why this matters:** The left code distinguishes existence from absence with a single unauthenticated request, so the naming convention turns into a full inventory. The right configuration removes both halves of the primitive: one hostname serves all tenants so a name cannot be guessed, and every failure is indistinguishable, so probing reveals nothing.

## When It Is NOT This Issue

- **An `AccessDenied` on an enumeration call.** That is the control working; the finding would need an allowed call that returns more than intended.
- **Public DNS records for services that are meant to be public.** A `www` record is not reconnaissance; the finding is an internal hostname exposed.
- **A certificate transparency entry for a public wildcard.** CT logging is mandatory for publicly trusted certificates.
- **A resource listing that returns only resources the caller already owns.** That is scoped authorisation.
- **Rate-limited enumeration attempts.** The limit is a control; report the attempts and the throttling rather than the enumeration.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cloud-recon-and-enumeration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cloud-recon-and-enumeration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cloud-recon-and-enumeration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-storage-and-metadata-abuse`](../cloud-storage-and-metadata-abuse/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-recon-and-enumeration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 37 |
| Distinct dataset sources | 5 |
| Top sources | bugbounty-hunter-v1 (32), CYBER_CPT/nuclei_templates (2), CYBER_CPT/github_security_md (1), CYBER_CPT/bishop_fox (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
