---
name: cloud-forensics-and-acquisition
description: "Acquires evidence from cloud environments: snapshot and log preservation, provider tooling constraints and multi-tenant evidence boundaries. Use when evidence lives in cloud infrastructure."
family: digital-forensics
tier: core
triggers: ["cloud forensics", "cloud acquisition", "snapshot evidence"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Cloud Forensics and Acquisition - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Cloud acquisition is not imaging; it is a set of provider API calls whose output you must then hash and defend, and the control plane that performed the call is itself evidence. An EBS snapshot captures only blocks written to the volume at snapshot time — page cache, in-memory sessions and anything the guest never flushed are absent — which is why the same runbook also captures a memory image when the instance is still running. CloudTrail management events answer "who called which API from where", while S3 data events answer "who read which object" and are off unless explicitly enabled, so a claim about object access made from management events alone is a claim about nothing. CloudTrail log-file integrity validation produces digest files signed with SHA-256 with RSA, letting `aws cloudtrail validate-logs` prove that a delivered file was not altered after delivery; it proves nothing about events that were never recorded. Event history retains 90 days of management events per Region and excludes read-only events in the console view by default, so an export made with default filters is silently incomplete. Multi-tenant boundaries cap what you can obtain: provider-managed services may expose only a control-plane record, a shared-responsibility log may be unreachable without the provider, and cross-account snapshot sharing requires the recipient to re-encrypt with its own key before a snapshot encrypted with a customer-managed key can be mounted. The practical consequence is that cloud evidence has a hard floor: you can prove what the control plane recorded inside retention, and you cannot prove absence outside it.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the instance is still running **THEN** snapshot every attached volume first and capture memory second, before any containment action that terminates, reboots or detaches — because a stop command destroys the memory image and a detach changes the volume's attachment record. **IF** the instance is already gone **THEN** branch to snapshots, provider logs and object versions only, and state in the output that process state is unrecoverable.
2. **IF** you need a defensible timeline **THEN** use CloudTrail as the spine, not as the whole record: pair it with VPC Flow Logs for network reach, S3 server access logs or data events for object reads, and the service's own audit log (for example an identity provider's sign-in log) for authentication. Any single source is a partial view and the output must say which ones were unavailable.
3. **IF** evidence must survive review **THEN** copy artifacts into a dedicated account or bucket with S3 Object Lock in governance or compliance mode, versioning enabled and MFA delete where offered, then hash at acquisition and re-hash on every move. **IF** you cannot make the original immutable **THEN** work on a copy of a copy and say so.
4. **IF** the artifact is a snapshot **THEN** restore it to a new volume in an isolated account and mount read-only; never attach the snapshot's volume to a live instance in the source account, because that instance's own activity writes to the same volume family and to the same CloudTrail the review depends on.
5. **IF** log integrity matters **THEN** run `aws cloudtrail validate-logs` over the delivered range and record which files failed; **IF** validation fails or digests are missing **THEN** treat the affected window as `Inconclusive`, not as clean.
6. **IF** the question reaches past 90 days, past the trail's configured retention, or into a Region you did not export **THEN** report `INCONCLUSIVE (Retention Gap)` rather than concluding absence.
7. **IF** telemetry source covering `snapshot` / `log export` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the exact API calls and integrity checks | [`QUERIES.md`](QUERIES.md) | Snapshot, validate-logs and export classes |
| Need CLI flags and IAM preconditions | [`TOOLS.md`](TOOLS.md) | `aws` subcommands and read-only role shape |
| Evidence lives in a SaaS workspace rather than IaaS | [`saas-workspace-and-entra-unified-audit-forensics`](../saas-workspace-and-entra-unified-audit-forensics/SKILL.md) | Unified audit log ownership sits with that slug |
| Need the disk-level analysis after a snapshot restore | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | Filesystem parsing and timeline construction |
| Need memory from a still-running instance | [`memory-forensics`](../memory-forensics/SKILL.md) | Acquisition tooling and volatile ordering |
| Containment decisions on cloud identity | [`cloud-incident-response-identity-containment`](../../incident-response/cloud-incident-response-identity-containment/SKILL.md) | Credential revocation sequencing |
| Need to understand the provider's own event taxonomy | [`cloud-detection-and-logging`](../../detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Which log answers which question |
| Need to know what an intrusion typically leaves | [`SCENARIOS.md`](SCENARIOS.md) | Case cards with provider-specific shapes |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the account ID, Region, resource ARNs, snapshot IDs and the SHA-256 of every exported file. Record which role performed the collection so the action is attributable in CloudTrail after the fact, and verify that the evidence bucket is in a different account from the compromised one — a bucket in the suspect account can be emptied by the suspect.
2. **Choose the branch from what the provider still holds.** Running instance: snapshot plus memory plus live logs. Stopped instance: snapshot only, and say memory is gone. Terminated instance: snapshots, provider logs, object versions, and whatever the workload shipped to a log archive before termination.
3. **Establish a baseline-versus-probe differential.** Baseline is the account's own earlier period, or a peer account with the same baseline template. Probe is the incident window. The finding is a delta in principal, source IP, user agent or API set — an API call that is new for that principal, not an API call that is frequent.
4. **Name the stop condition.** Declare `Inconclusive` when the trail was not enabled for the affected Region or service, when data events were off for the bucket in question, when event history has aged out, when the log's integrity validation fails, or when the only record of an action is the actor's own agent on a host the actor controlled. Each of these is a limit of the evidence, not an absence of activity.
5. **State what counts as proof.** Proof is two independently written provider records naming the same principal and resource inside a stated tolerance: a CloudTrail event plus the service's own audit entry, or a control-plane call plus the VPC flow that carried its traffic. A single CloudTrail event proves the API was called by that principal — not that the call succeeded, and not that the caller was human.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `CreateSnapshot` followed by `ModifySnapshotAttribute` to another account | CloudTrail management event | A volume was snapshotted and shared outward; proves acquisition or exfiltration of disk content, not what the disk held |
| `GetSecretValue` burst by one principal across many secret ARNs | CloudTrail data or management event | Credential harvesting at scale by that principal inside the recorded window |
| `PutBucketPolicy` or `PutPublicAccessBlock` change on an evidence or log bucket | CloudTrail management event | The logging or retention control itself was altered, which invalidates later absence claims for that bucket |
| CloudTrail digest file mismatch under `validate-logs` | CloudTrail log integrity chain | A delivered log file was modified or removed after delivery, on that trail and range |
| VPC Flow Log record with `REJECT` for an internal port sweep from one ENI | VPC Flow Logs | Network reach was attempted from that interface at that time; says nothing about application-layer success |
| Snapshot with `Encrypted=false` on a volume whose siblings are encrypted | EBS snapshot metadata | A protection control was removed before or during acquisition, on that volume |
| Access log line for `GET` on an object in a bucket with data events disabled | S3 server access log | The request happened even though CloudTrail cannot show it; delivered best-effort, so a missing line proves nothing |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Reads the default console view and treats it as the record.
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue
# No --start-time/--end-time, default Region only, and the console default hides
# read-only events. The result is a partial list presented as a complete one,
# with no statement of retention, Region coverage or integrity state.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
REGION="${REGION:?set REGION}"
START="${START:?ISO8601 UTC}"; END="${END:?ISO8601 UTC}"
OUT="ct-${REGION}-${START//:/}.json"

aws cloudtrail lookup-events --region "$REGION" \
  --start-time "$START" --end-time "$END" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --output json > "$OUT"
sha256sum "$OUT" | tee -a evidence-manifest.txt

aws cloudtrail validate-logs --region "$REGION" \
  --trail-name "$(aws cloudtrail describe-trails --region "$REGION" \
      --query 'trailList[0].Name' --output text)" \
  --start-time "$START" --end-time "$END"

jq -r '.Events[].CloudTrailEvent | fromjson
       | [.eventTime, .userIdentity.arn, .sourceIPAddress, .userAgent, .errorCode]
       | @tsv' "$OUT" | sort | uniq -c | sort -rn | head -40
```

**Why this matters:** the strong form bounds the window explicitly, hashes the export at acquisition, validates the trail's integrity chain over the same range, and groups by principal and source so the finding is a delta rather than a list — and every one of those steps is recorded for review.

## When It Is NOT This Issue

- **Automation and service roles:** scheduled jobs, autoscaling lifecycle hooks and CI runners legitimately call `CreateSnapshot`, `GetSecretValue` and `PutBucketPolicy`. Compare the principal against the account's documented automation inventory before treating an API burst as hostile.
- **Provider-initiated events:** AWS service-linked roles, support access with an authorised engagement, and provider maintenance appear in CloudTrail with a provider principal. Read `userIdentity.invokedBy` and the `sessionContext` before attributing the call to a person.
- **Region and clock differences:** CloudTrail records UTC while S3 access log lines carry their own offset, and a workload writing local time into its own logs will not line up. Normalise before correlating, and do not call a two-hour gap a deleted window until the offsets are checked.
- **Retention and tiering:** an empty result for a 120-day-old event is expected because event history holds 90 days; a lake-tier query that returns nothing may simply be querying a tier whose data was never routed there. Retention is not tampering.
- **Snapshot cost and space:** a volume restored from a snapshot without `--volume-type` and size adjustments can fail to mount cleanly, and a compressed or sparse filesystem may look mostly empty. Verify with the filesystem tool before concluding the volume was wiped.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `snapshot` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** account, Region, resource IDs and the SHA-256 of every export are recorded, and the collecting role is named so its own actions are attributable.
- [ ] **Coverage stated:** for each conclusion, the output names which of CloudTrail management events, data events, flow logs, service audit logs and object access logs were actually enabled for that window.
- [ ] **Differential defined:** a baseline period or peer account was compared against the incident window, and the reported finding is the delta by principal, source or API set.
- [ ] **Stop condition cleared or declared:** retention, integrity-validation failure, disabled data events and terminated-instance memory loss were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: cloud-forensics-and-acquisition
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-forensics-and-acquisition` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — collection calls are read-only or snapshot-only, never a detach, terminate or policy change on the source account.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/nuclei_templates (4), CYBER_CPT/gh_advisories (2), OffsecCyber (1), Forensic_Toolkit_Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 1 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
