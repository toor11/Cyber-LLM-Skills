---
name: cloud-incident-response-audit-reconstruction
description: Cloud audit log reconstruction. Covers rebuilding an actor timeline from control plane and data plane logs across providers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: incident-response
tier: leaf
triggers: ["cloud audit reconstruction", "cloudtrail timeline", "activity log timeline"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [cloud-incident-response, cloud-incident-response-identity-containment, incident-response-playbooks, ir-triage-and-timeline]
parent: cloud-incident-response
---

# Cloud Incident Response Audit Reconstruction - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md)

## Mechanism and Preconditions

Reconstruction is the act of turning a set of provider audit records into a defensible sequence of actor actions. It is not log viewing: it is joining records that were emitted by different services, with different schemas, different clocks and different coverage defaults, into one timeline where each entry can be attributed to a principal and a request. Three properties of cloud audit data govern the work. Coverage is per-plane: management events are recorded by default in a bounded history, while data events must be explicitly enabled per resource type and are absent from event history altogether, so an object-read timeline requires a data-event trail or an event data store that existed before the window. Attribution is per-session: the calling principal in a record is often a role session whose `accessKeyId` is unique to that assumption, so grouping by access key rather than by role name is what separates two actors using the same role. Timing is not uniform: `eventTime` is when the service accepted the call, delivery lag puts the record in the destination bucket later, and identity-provider records carry their own timestamps, so a naive merge of two exports will mis-order events by minutes to hours unless the join is explicit. The precondition that makes reconstruction possible at all is that the records were collected and retained; where they were not, the honest output is a timeline with declared holes, not a smooth narrative.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `cloud-incident-response-audit-reconstruction` **THEN** start at parent class [`cloud-incident-response`](../cloud-incident-response/SKILL.md) first.
2. **IF** the question is "when did it start" **THEN** anchor on the earliest record with a reliable clock — usually an identity-provider sign-in or a management event — and build outward; **IF** the earliest record is in a data-event table, verify that the trail existed before that record, or the "start" is really the start of logging.
3. **IF** two exports disagree on ordering for the same action **THEN** join on request id or correlation id rather than on time, and keep both timestamps in the output with their source named.
4. **IF** the window crosses a retention boundary or a trail was stopped inside it **THEN** mark that interval as unreconstructable rather than interpolating through it.
5. **IF** the reconstruction is for a legal, regulatory or insurer audience **THEN** freeze the input exports with hashes and record the query text and parameters used, so the timeline is reproducible by a third party.
6. **IF** telemetry source covering `control plane` / `data plane` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md).
8. **IF** required preconditions for `cloud-incident-response-audit-reconstruction` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`cloud-incident-response`](../cloud-incident-response/SKILL.md) | General class triage before variant specifics |
| Need to revoke rather than reconstruct | [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) | Revocation primitives and ordering |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for join keys and coverage holes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Query and export entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the record set before joining anything.** For the accounts and window in scope, list which tables exist, which planes they cover, their retention start and their clock source. An event data store created mid-incident yields a timeline that begins at its creation, and every reconstruction that omits this produces a false onset.
2. **Choose the join key, not the sort order.** Records from different services share at most one of: request id, correlation id, session access key, or principal plus resource plus minute. Pick the strongest available key and state it; sorting a union by timestamp without a key silently interleaves unrelated actors.
3. **Establish the baseline activity set for the principals involved.** Enumerate each principal's normal operations, source range, user-agent and hourly rate over a quiet period. The timeline is then the deviation from that envelope, which keeps routine automation out of the narrative and makes the remaining entries defensible in isolation.
4. **State the stop condition.** Stop when every record in the window has been either attributed to a principal with a documented owner or explicitly marked unattributed, and when every gap has a cause: not collected, not retained, logging stopped, or delivery pending. A timeline with unlabelled gaps is not finished.
5. **Prove the timeline is reproducible.** Record the exact query text, the parameters, the export timestamps and the hash of each input file. The proof standard for a reconstruction is that a second analyst running the recorded queries against the preserved inputs produces the same ordered output — not that the narrative reads well.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Records grouped by `userIdentity.accessKeyId` within one role name | Management event session field | Distinct role assumptions are distinct actors or sessions; grouping by role name merges them and hides a second actor |
| Gap in delivery evidenced by `LatestDeliveryTime` earlier than the export request | Trail status | The absence of records after that point is a delivery gap, not the end of actor activity |
| Data-event table creation timestamp compared with the first object-read record | Event data store or trail configuration record | Whether the "first read" is the first read or the first logged read, which changes the whole theft-scope claim |
| Identity-provider sign-in record joined to cloud `AssumeRole` by principal and minute | IdP sign-in log plus management event | That a cloud API call was preceded by a real authentication of that principal, distinguishing human-driven from pre-staged access |
| `errorCode` distribution per principal per operation | Management event with error field | Enumeration and permission-discovery behaviour, because a burst of `AccessDenied` across many operations is probing rather than use |
| Resource ARN cardinality per principal per hour | Management or data event resource field | Breadth of action: one bucket versus every bucket, one secret versus every secret, which is what scope claims rest on |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK RECONSTRUCTION:
union all_exports order by event_time
# Different services emit different clocks and different clocks skew;
# role sessions share a role name, so two actors merge into one line;
# delivery lag reorders the last hours; a stopped trail leaves a hole
# that the sort happily interpolates through.
```

**High-Signal Grounded Artifact:**

```sql
-- One row per actor action, keyed on the strongest available identifier,
-- with the source and its clock preserved rather than flattened.
WITH mgmt AS (
  SELECT event_time AS ts, 'mgmt' AS src,
         coalesce(json_extract_scalar(useridentity, '$.accessKeyId'), 'unknown') AS session_key,
         json_extract_scalar(useridentity, '$.arn') AS principal,
         event_name AS action, error_code AS err,
         json_extract_scalar(response_elements, '$.requestId') AS req_id,
         json_extract_scalar(resources[1], '$.ARN') AS resource
  FROM cloudtrail_management_events
  WHERE event_time BETWEEN timestamp '2026-10-01 00:00:00' AND timestamp '2026-11-14 00:00:00'
),
data_plane AS (
  SELECT event_time AS ts, 'data' AS src,
         coalesce(json_extract_scalar(useridentity, '$.accessKeyId'), 'unknown') AS session_key,
         json_extract_scalar(useridentity, '$.arn') AS principal,
         event_name AS action, error_code AS err,
         json_extract_scalar(response_elements, '$.requestId') AS req_id,
         json_extract_scalar(resources[1], '$.ARN') AS resource
  FROM cloudtrail_data_events
  WHERE event_time BETWEEN timestamp '2026-10-01 00:00:00' AND timestamp '2026-11-14 00:00:00'
)
SELECT ts, src, session_key, principal, action, err, req_id, resource
FROM (SELECT * FROM mgmt UNION ALL SELECT * FROM data_plane)
ORDER BY session_key, ts, req_id;
```

**Why this matters:** the ordered unit is the session, not the timestamp, so two actors behind one role stay separate, and the `src` column keeps the plane visible so a missing data-event row is read as a coverage fact rather than an absence of reads.

## When It Is NOT This Issue

- **Delivery lag misread as a stop:** the last hours of a trail frequently appear empty because the batch has not landed. Check `LatestDeliveryTime` and the `NextToken` of the lookup before declaring activity ceased.
- **Duplicate organisation and account trails:** the same event is delivered to both the account trail and the organisation trail, doubling every count and inventing a burst. Deduplicate on request id before any volume claim.
- **Two exports from different clock sources:** provider `eventTime`, IdP sign-in time and SIEM ingest time differ by seconds to hours. A merge that uses ingest time will place the same action in two places and produce an apparent impossible-travel pattern.
- **Stale token accepted by a legacy endpoint:** a record from an old access key with a scheduled integration user-agent looks like persistence. Attribute by principal owner and destination before treating it as actor activity.
- **Automation that rotates keys on schedule:** secrets managers and CI pipelines create and delete keys continuously, so a key-creation burst is often routine. Check the cadence and the principal owner against the inventory.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `control plane` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Plane coverage mapped:** management and data event tables were each confirmed to exist and to cover the window, and any plane without coverage is marked in the timeline rather than omitted.
- [ ] **Join key stated:** the identifier used to relate records (request id, session access key, or principal-resource-minute) is named, and records that share no key are kept separate instead of time-sorted together.
- [ ] **Retention boundary recorded:** the earliest retained record per table is noted, so no claim extends before it as if it were observed.
- [ ] **Gaps attributed to a cause:** every interval without records is labelled not collected, not retained, logging stopped, or delivery pending.
- [ ] **Reproducibility captured:** query text, parameters, export timestamps and input hashes are stored with the timeline so a second analyst can regenerate it.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: cloud-incident-response-audit-reconstruction
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`cloud-incident-response`](../cloud-incident-response/SKILL.md) - Incident Response (core)
- [`cloud-incident-response-identity-containment`](../cloud-incident-response-identity-containment/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-incident-response-audit-reconstruction` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/expku (3), CYBER_CPT/wiz_research (3), CYBER_CPT/hacktricks (1), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
