---
name: cloud-incident-response
description: "Responds to cloud incidents: identity-based containment, audit log reconstruction, snapshot acquisition and service-specific evidence sources. Use when the incident involves a cloud environment."
family: incident-response
tier: core
triggers: ["cloud incident response", "aws ir", "azure ir", "cloud compromise"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [cloud-incident-response-identity-containment, cloud-incident-response-audit-reconstruction, incident-response-playbooks, ir-triage-and-timeline]
---

# Cloud Incident Response - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md)

## Mechanism and Preconditions

A cloud incident is an API-access incident. The actor rarely owns a persistent foothold in the classic sense; they own a credential that can call a control-plane API, and their impact is bounded by that credential's permissions and by how long it stays valid. Two structural properties shape every response. First, control-plane and data-plane logging have different defaults and different costs: management events are recorded by default in a limited history, while data events — the S3 `GetObject` reads and DynamoDB item operations that constitute theft — are off by default on trails and absent from event history entirely, so the most important evidence class for a data-theft case is usually the one that was never enabled. Second, containment is a policy operation that may itself destroy the responder's access, and it is frequently partial: revoking an access key does not terminate an assumed-role session already issued, disabling a user does not revoke a token minted by a federated identity provider, and changing a security group does not necessarily tear down established flows. The precondition that makes the incident containable and reconstructable is therefore pre-existing: multi-region trail coverage with log-file validation and an independently controlled destination, identity-provider audit retention, and a written record of which principal owns which role — because in cloud, the attacker and the responder call the same API, and the only way to tell their actions apart afterwards is the audit record.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `identity-containment` **THEN** switch to [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) (1 hop).
2. **IF** the target specifically involves `audit-reconstruction` **THEN** switch to [`cloud-incident-response-audit-reconstruction`](../cloud-incident-response-audit-reconstruction/SKILL.md) (1 hop).
3. **IF** the evidence question is "what did the actor read" **THEN** establish whether data-event logging existed for those resources before the window; **IF** it did not, report the theft scope as `Inconclusive (Data-Event Gap)` rather than inferring it from management events.
4. **IF** the credential is a long-lived access key **THEN** branch to key rotation and policy detach; **IF** it is an assumed role or federated session **THEN** branch to session revocation by token issue time, because deleting the underlying user does not touch the session.
5. **IF** containment will remove the principal the responder is currently using, or a break-glass path **THEN** stage the replacement authority first; a lockout during an incident costs more than the hours saved.
6. **IF** the workload is a managed service with no host access **THEN** branch to platform logs and configuration history; there is no memory to capture and no disk to image, and promising an acquisition that does not exist delays the real work.
7. **IF** telemetry source covering `access key revoke` / `audit log` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md).
9. **IF** required preconditions for `cloud-incident-response` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `cloud-incident-response-identity-containment` | [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cloud-incident-response-audit-reconstruction` | [`cloud-incident-response-audit-reconstruction`](../cloud-incident-response-audit-reconstruction/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for coverage, control plane and snapshot attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Provider CLI read/verify entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Prove the log estate before reading it.** For each account, subscription or project in scope: which trail or diagnostic setting exists, whether it is multi-region and organisation-wide, whether log-file validation is on, where the destination is, who can delete it, and what the retention is. A trail whose destination bucket sits in the compromised account is deletable by the actor and cannot be relied on as evidence.
2. **Branch on credential type and on plane.** Long-lived key, assumed role, federated session, service-account token and workload identity each need a different revocation primitive, and control-plane containment (policy) behaves differently from data-plane containment (bucket policy, resource policy, network path). Name the branch and the primitive before acting.
3. **Define the tenant baseline before calling an API call anomalous.** Most cloud environments have noisy automation: deployment pipelines, backup jobs, cost tooling, autoscaling, and CI roles that legitimately call `CreateAccessKey`, `PutBucketPolicy` or `StopInstances` on schedule. Establish each principal's normal API set, source-address range, user-agent and hourly call volume; the finding is a principal calling an operation outside its own historical set from an address outside its historical range, not the operation being inherently suspicious.
4. **State the stop condition.** Stop when the compromised credential's last valid token has expired or been revoked with an audit record confirming it, the actor's persistence objects (additional keys, roles, trust policies, identity-provider entries) are enumerated and removed, and the data-theft scope is either proven or declared unreconstructable. Do not stop merely because the alert closed.
5. **Require an event proving effect.** A `PutRolePolicy` call that returned 200 is not evidence that access was denied; the evidence is a later `AccessDenied` from the actor's principal in the audit record, or the absence of any successful call from that principal after the revocation timestamp. Snapshots are proven by a completed status with an accessible copy, not by a console entry; copies are proven by a hash taken from the bytes actually read.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| `cloudtrail` `StopLogging`, `DeleteTrail`, `UpdateTrail` with `enableLogFileValidation` false, or the equivalent sink deletion | Control-plane management event | Deliberate reduction of audit visibility before or during other activity, and the start of an unlogged window that no later query can fill |
| Resource-access event on an object store where the request source is outside the workload's historic address set | Data-plane access log | Actual object reads by an unexpected principal — the theft itself, which management events cannot show |
| `AssumeRole` followed by API calls whose `userIdentity.accessKeyId` differs from the caller's own | Management event with session context | Session chaining: the actor is operating as a different principal than the one they authenticated as, which is why deleting the original key does not contain them |
| Access-key or client-secret creation by a principal that has never created one | Management event | Persistence independent of the password, which survives a credential rotation |
| Trust-policy or identity-provider modification on a role the workload uses | Management event | A cross-account or federated path that outlives the compromised credential and re-enters after containment |
| Snapshot or image export job completion status with destination and encryption key | Service API status or job log | Whether a usable preservation copy exists and whether it is decryptable by the responder, as opposed to merely created |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK TRIAGE / RULE:
# Alert on any CreateAccessKey or PutBucketPolicy in the account.
# Every pipeline, backup job and terraform run trips it, the queue floods,
# and the responder learns to close these without reading the principal.
```

**High-Signal Grounded Artifact:**

```sql
-- Principal-relative baseline: an operation outside the principal's own
-- historical set, or from an address outside its own historical range.
WITH hist AS (
  SELECT useridentity_arn,
         eventname,
         approx_percentile(source_ip_address, 0.99) AS usual_ip
  FROM cloudtrail_logs
  WHERE from_unixtime(eventtime) BETWEEN current_timestamp - interval '90' day
                                     AND current_timestamp - interval '2' day
  GROUP BY 1, 2
)
SELECT c.eventtime, c.useridentity_arn, c.eventname,
       c.source_ip_address, c.useragent, c.errorcode
FROM cloudtrail_logs c
LEFT JOIN hist h
  ON c.useridentity_arn = h.useridentity_arn
 AND c.eventname = h.eventname
WHERE from_unixtime(c.eventtime) > current_timestamp - interval '24' hour
  AND h.eventname IS NULL
ORDER BY c.eventtime DESC
LIMIT 200;
```

**Why this matters:** the strong form makes the principal its own baseline, so a privileged-but-routine call by the pipeline that always makes it is silent, while the same call by a principal with no history is the finding — and the output carries the principal and address needed to judge it.

## When It Is NOT This Issue

- **Deployment pipeline or infrastructure-as-code run:** CI roles call key creation, policy attachment and instance termination as their designed function, on schedule, from a stable runner range. Compare the principal's `useragent` and source range with the pipeline inventory before escalating.
- **Backup, DR or cost-optimisation automation:** snapshot creation, cross-region copy and instance stop/start are exactly the operations an attacker uses and exactly what these tools do hourly. The discriminator is the resource tag and the scheduled cadence, not the API name.
- **Planned DR test or migration dual-write:** a failover test produces cross-region reads and writes, new role assumptions and temporary policy changes in a narrow window. Check the change calendar and the test window boundary.
- **A stale token accepted by a legacy endpoint:** an old access key that a forgotten integration still uses looks like persistence and is actually an unowned workload. Attribute by user-agent and destination before treating it as actor infrastructure.
- **Region or provider status event:** a service disruption produces API error bursts and retry storms that page as anomalies. Confirm against the provider status feed and the error-code distribution — `Throttling` and `ServiceUnavailable` are not intrusion.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `access key revoke` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Log estate proven:** trail or diagnostic coverage, multi-region scope, validation state, destination ownership and retention were each confirmed for the accounts in scope, and gaps are named rather than assumed quiet.
- [ ] **Credential branch identified:** the compromised credential type (key, role session, federated token, workload identity) was determined and the matching revocation primitive named before any containment call.
- [ ] **Principal baseline established:** each implicated principal's historical API set, source range and user-agent were measured, so the finding is a principal-relative delta.
- [ ] **Persistence enumerated:** secondary keys, added roles, trust-policy changes and identity-provider entries created in the window were listed and dispositioned.
- [ ] **Effect attested:** every containment step has a corresponding audit event or an observed `AccessDenied`/absence-of-success from the actor's principal after the action timestamp.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: cloud-incident-response
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) - Incident Response (leaf)
- [`cloud-incident-response-audit-reconstruction`](../cloud-incident-response-audit-reconstruction/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-incident-response` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/nuclei_templates (4), CYBER_CPT/blackhills (3), OffsecCyber (2), hackerone_disclosed_reports (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
