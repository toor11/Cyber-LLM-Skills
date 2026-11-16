---
name: aws-attacks-s3-and-storage
description: AWS S3 and storage abuse. Covers bucket policy and ACL review, anonymous access, object versioning exposure, and presigned URL abuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["s3 bucket attack", "bucket policy", "presigned url", "s3 acl"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [aws-attacks, aws-attacks-iam-and-role-chaining, aws-attacks-compute-and-metadata, cloud-recon-and-enumeration]
parent: aws-attacks
---

# AWS Attacks S3 and Storage - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md)

## Mechanism and Preconditions

S3 exposure is decided by the interaction of four separate policy layers, and a finding needs the effective result rather than any one layer. The bucket policy grants at the resource; the identity policy grants at the principal; the ACL grants at the object or bucket for the legacy grantee model; and the Block Public Access setting can override all three by refusing public grants regardless of policy content. On top of those sit the bucket's own defaults: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`, each of which closes a different path, and account-level settings that apply to every bucket unless a bucket overrides them. The common real findings are a bucket policy with `Principal: "*"` that a later `RestrictPublicBuckets` setting neutralises (a non-finding that looks alarming), and a policy that grants to a specific role in another account with no `aws:PrincipalOrgID` condition (a real cross-tenant read that looks narrow). Encryption is a separate axis: SSE-S3, SSE-KMS with a bucket key, and SSE-C have different key-custody answers, and a bucket policy that allows `s3:GetObject` without requiring `s3:ExistingObjectTag` or TLS leaves the encryption default as the only control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the bucket policy has a wildcard principal **THEN** read the four Block Public Access flags before calling it public; an enabled `RestrictPublicBuckets` neutralises most of them.
2. **IF** the grant is to another account's role **THEN** check for `aws:PrincipalOrgID` or `aws:SourceAccount`; absent them the grant is cross-tenant.
3. **IF** the question is object-level **THEN** check the ACL layer separately; a public object ACL can exist while the bucket policy is closed.
4. **IF** the concern is encryption **THEN** record the default encryption and whether a bucket key is used, because the answer changes key-custody review.
5. **IF** the review is about who can read within the account **THEN** start at [`aws-attacks`](../aws-attacks/SKILL.md); this skill is the resource-policy and public-access layer.
6. **IF** the storage is not S3 **THEN** record which service it is; the policy grammar differs and the Block Public Access equivalent may not exist.
7. **IF** every public path is closed by an account-level setting **THEN** record `Verified Safe` and cite the setting, since a future account change would reopen it.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`aws-attacks`](../aws-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the effective public-access state first.** Account-level and bucket-level Block Public Access flags, then the bucket policy, then the ACLs. The order matters because the flags override the policies.
2. **Resolve the effective grant.** For each statement, the principal, the action, the resource, and the conditions. A grant to `*` with `aws:PrincipalOrgID` is internal; a grant to a specific role without one is external.
3. **Choose the branch.** Public policy, cross-account grant without an org condition, ACL grant, or encryption-default dependency.
4. **Define the baseline-vs-probe differential.** Baseline: an unauthenticated `GET` to a known object key, which returns 403 on a closed bucket. Probe: the same request against an object the policy appears to grant. A 200 is the finding; a 403 with `AccessDenied` is the control, and the error code tells you which layer refused.
5. **Name the stop condition.** Stop at the first object readable without credentials, or the first confirmed cross-account grant. Do not enumerate object keys.
6. **State the proof.** Report the statement, the flags that do or do not override it, the request that succeeded or the error that refused it, and the minimal policy or flag change. Name the layer that made the decision.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `"Principal": "*"` with `s3:GetObject` and no conditions | Public read at the resource layer, unless Block Public Access overrides it | Bucket policies on static-site or CDN origins |
| `RestrictPublicBuckets: true` at the account level | Every public policy in the account is neutralised, which turns the finding into a non-finding | Account-level S3 public access settings |
| A grant to `arn:aws:iam::444455556666:role/x` with no `aws:PrincipalOrgID` | Cross-tenant read that looks narrow but has no organisational bound | Vendor and partner data shares |
| `s3:x-amz-server-side-encryption` condition absent on a `PutObject` grant | The writer chooses the encryption, including none if the bucket default is weak | Ingest buckets written by external systems |
| A public object ACL with `BlockPublicAcls: true` | The ACL is stored but ignored, which is why the object is not actually public | Legacy ACL usage |
| `aws:SecureTransport: false` deny statement present | TLS is enforced at the resource, which is the correct shape | Hardened bucket policies |

## Worked Contrast

**Vulnerable: public read policy with no conditions and default encryption unset**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::acme-reports/*"
  }]
}
```

```text
# Block Public Access at the account level, all four flags off
aws s3control get-public-access-block --account-id 111122223333
# -> no PublicAccessBlockConfiguration returned
```

**Hardened: no public principal, org-scoped grants, TLS enforced, SSE-KMS default**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "OrgReadOnly", "Effect": "Allow",
     "Principal": "*",
     "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::acme-reports/*",
     "Condition": {
       "StringEquals": {"aws:PrincipalOrgID": "o-example123"},
       "Bool": {"aws:SecureTransport": "true"}
     }},
    {"Sid": "DenyPlaintext", "Effect": "Deny",
     "Principal": "*",
     "Action": "s3:*",
     "Resource": ["arn:aws:s3:::acme-reports", "arn:aws:s3:::acme-reports/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  ]
}
```

```text
aws s3api put-bucket-encryption --bucket acme-reports \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/reports"},"BucketKeyEnabled":true}]}'
```

**Why this matters:** The left policy grants read to every principal on the internet and nothing at the account level overrides it, so the finding is a single unauthenticated request. The right policy keeps the wildcard principal but constrains it to the organisation and to TLS, adds an explicit deny for plaintext, and sets a KMS default so the encryption is not left to the writer.

## When It Is NOT This Issue

- **A wildcard-principal policy with `RestrictPublicBuckets` enabled at the account level.** The flag overrides the grant; record the flag as the control rather than filing the policy.
- **A public object ACL when `IgnorePublicAcls` is on.** The ACL is inert.
- **A grant to another account with `aws:PrincipalOrgID`.** That is an intra-organisation share, not a cross-tenant one.
- **A bucket used only as a CloudFront origin with an origin access control.** The bucket policy grants the distribution, and direct public access is denied.
- **A `Deny` statement with a wildcard principal.** Denies are meant to be broad.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `aws-attacks-s3-and-storage` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `aws-attacks-s3-and-storage` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: aws-attacks-s3-and-storage
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`aws-attacks-iam-and-role-chaining`](../aws-attacks-iam-and-role-chaining/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`aws-attacks-compute-and-metadata`](../aws-attacks-compute-and-metadata/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `aws-attacks-s3-and-storage` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/oxdf (2), CYBER_CPT/github_security_md (2), bug-bounty-pentest-en (1), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
