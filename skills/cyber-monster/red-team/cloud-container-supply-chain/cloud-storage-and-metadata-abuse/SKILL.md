---
name: cloud-storage-and-metadata-abuse
description: "Exploits public and misconfigured cloud storage plus instance metadata: anonymous buckets, ACL and policy gaps, signed URL abuse and IMDS credential theft. Use when storage or compute metadata may be reachable."
family: cloud-container-supply-chain
tier: core
triggers: ["cloud storage abuse", "public bucket", "metadata credential theft", "imds abuse"]
cwe: [CWE-284]
owasp: []
attack: [T1552]
capec: [CAPEC-122]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
---

# Cloud Storage and Metadata Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Storage and metadata abuse covers the paths that reach data or credentials without an identity policy decision. The public-object path is the simplest: a bucket, blob container, or GCS bucket whose ACL or policy grants `AllUsers`, which is discoverable by name and readable without credentials. The signed-URL path is subtler: a presigned URL or SAS token carries its own authority, so a long expiry or a wildcard resource in the signing policy grants access that no policy review sees, and the URL is often logged in referrers and browser history. The metadata path is the credential one: the instance metadata service, the container credential endpoint, and the GCP metadata server all answer requests from inside the workload, so any request-forgery primitive reaches them. The key-custody path is the one most often missed: a storage bucket used as the KMS key store or the Terraform state backend holds material that is more sensitive than the data the bucket appears to hold. The review question is which of these paths exists, and the answer is checkable by a few read-only requests rather than by a policy reading.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the object is readable without credentials **THEN** the finding is complete; the path is one request and needs no policy analysis.
2. **IF** the mechanism is a presigned URL or SAS token **THEN** read the expiry and the signing policy; a wildcard resource in the signature is the finding.
3. **IF** the concern is credentials rather than data **THEN** switch to the compute skill for the metadata endpoint ([`aws-attacks-compute-and-metadata`](../aws-attacks-compute-and-metadata/SKILL.md)) or the workload identity skill for the container path.
4. **IF** the bucket holds state, keys, or backups **THEN** the classification drives severity; name what the bucket actually contains before the finding.
5. **IF** the storage is S3 specifically **THEN** start at [`aws-attacks-s3-and-storage`](../aws-attacks-s3-and-storage/SKILL.md) for the four-layer policy interaction.
6. **IF** the mechanism is a signed URL in a log or a referrer **THEN** the finding is the exposure channel plus the expiry, not the signature algorithm.
7. **IF** every object requires an authenticated request and no signed URL with a long expiry exists **THEN** record `Verified Safe` with the request and the response code.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Test the anonymous path first.** One unauthenticated request per object class. A `403` with an `AccessDenied` body is a control; a `200` is the finding, and the body proves it.
2. **Inventory signed URLs and tokens.** Grep the application for presigning calls and read the expiry parameter and the policy document. A ten-year expiry is equivalent to public for practical purposes.
3. **Classify the bucket's content.** State, keys, backups, or public assets. The severity follows the content, not the ACL.
4. **Define the baseline-vs-probe differential.** Baseline: the object as served to an authorised caller. Probe: the same object requested without credentials. Identical content in both is the finding.
5. **Name the stop condition.** Stop at the first object readable without credentials or the first signed URL whose scope exceeds its stated purpose. Do not download more than one object to prove the path.
6. **State the proof.** Report the URL, the response code, the object class, and the access mechanism (ACL, policy, signed URL). If every path requires credentials, record the negative with the request and its error code.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A `200` on an unauthenticated `GET` of an object | Public read at whatever layer granted it, which is the finding regardless of which layer | S3, Blob Storage, GCS |
| `generate_presigned_url` with `ExpiresIn=315360000` | A ten-year signed URL that is effectively a public credential, and it appears in logs | boto3, Azure SAS, GCS signed URLs |
| A SAS token with `sp=r` and `sr=c` and no IP restriction | Container-wide read from any address until expiry | Azure Blob Storage |
| A bucket that is the Terraform state backend | State contains resource identifiers and often secrets, so read access is equivalent to infrastructure control | Terraform backends |
| A storage bucket holding KMS key material or backups | The bucket's classification is higher than its name suggests | Key stores, database backup targets |
| An `AllUsers` or `allAuthenticatedUsers` grant in the ACL | Public grant at the ACL layer, which the policy layer may not show | GCS, S3 legacy ACLs |

## Worked Contrast

**Vulnerable: public object plus a decade-long presigned URL in application code**

```python
# The bucket policy allows public read, and the application also mints URLs that
# never expire, which are logged in referrers and shared in tickets.
import boto3

s3 = boto3.client("s3")

def download_link(key: str) -> str:
    return s3.generate_presigned_url("get_object",
                                     Params={"Bucket": "acme-reports", "Key": key},
                                     ExpiresIn=315360000)      # ten years
```

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::acme-reports/*"
  }]
}
```

**Hardened: no public principal, short-lived signed URLs, and a download path that authorises per request**

```python
# The bucket is private; the application checks authorisation and mints a URL that
# expires in minutes and is bound to one object.
import boto3
from datetime import timedelta

s3 = boto3.client("s3")

def download_link(key: str, subject: str) -> str:
    require_access(subject, key)                   # authorisation decision
    return s3.generate_presigned_url("get_object",
                                     Params={"Bucket": "acme-reports", "Key": key},
                                     ExpiresIn=int(timedelta(minutes=5).total_seconds()))
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::acme-reports", "arn:aws:s3:::acme-reports/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  ]
}
```

**Why this matters:** The left configuration exposes the objects twice — once through a public policy and again through URLs that never expire — so revoking the policy does not revoke the links already handed out. The right configuration keeps the bucket private and makes each link an authorisation decision with a five-minute window, so exposure is bounded by the moment of use.

## When It Is NOT This Issue

- **A public bucket that serves only static marketing assets.** The classification is public by design; the finding would be a non-public object inside it.
- **A presigned URL with a fifteen-minute expiry generated per request after an authorisation check.** That is the correct pattern.
- **A bucket policy with a wildcard principal and an `aws:PrincipalOrgID` condition.** Internal sharing, not public access.
- **A signed URL found in a log for an object that has since been deleted.** The exposure is historical; report the deletion rather than the URL.
- **A Terraform state bucket with encryption and a restrictive policy.** The classification is high but the controls are present.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cloud-storage-and-metadata-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cloud-storage-and-metadata-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cloud-storage-and-metadata-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1552]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-storage-and-metadata-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1552`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 6 |
| Top sources | bugbounty-hunter-v1 (2), CYBER_CPT/oxdf (2), CYBER_CPT/github_security_md (2), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
