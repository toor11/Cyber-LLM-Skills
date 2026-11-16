---
name: insider-threat-investigation
description: "Investigates insider threat: behavioural indicators, data access patterns, evidence handling constraints and coordination with HR and legal. Use when an employee or contractor is suspected."
family: incident-response
tier: core
triggers: ["insider threat", "insider investigation", "data theft employee"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Insider Threat Investigation - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

An insider investigation differs from every other incident type in one structural way: the activity is authorised. The account is valid, the access is provisioned, the device is issued, and the traffic is inside the perimeter. No control is being violated at the point of observation, which means detection rests entirely on a deviation from the person's own established pattern — a volume, a timing, a data-set breadth, or a destination that their history does not contain — rather than on any signature of misuse. This is why the baseline is the case: without a per-user normal for file access breadth, download volume, print activity, USB use and cloud-sync destination, every alert is a judgement about a colleague made without evidence. The second structural difference is that the subject has rights. NIST's guidance on integrating forensic techniques into incident response is explicit that the decision to collect to an evidentiary standard should be taken before collection, in line with policy and legal advice, and that a legal hold suspends routine deletion for the covered categories. Contemporary investigative practice adds the sequencing that makes findings usable: legal counsel confirms the jurisdictional basis and the notice position, a hold is issued to the system owners who can actually suspend deletion, HR is engaged as a decision-maker rather than a bystander, and collection is covert where covertness is lawful so the subject is not tipped into destroying evidence. The precondition for a defensible outcome is therefore a documented threshold — set in advance — that marks when a signal moves from passive monitoring into active investigation, because that crossing is what triggers the legal gate.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the signal has not yet crossed the documented investigation threshold **THEN** keep it in passive monitoring and record the corroboration; **IF** it has crossed **THEN** stop and obtain legal review before any further collection, because collection without that gate can make the findings unusable.
2. **IF** the subject may still be employed and active **THEN** assume any visible change in permissions, monitoring or access will be noticed; prefer covert collection of existing telemetry over new tooling on the subject's device.
3. **IF** a legal hold has not been issued to the system owners **THEN** issue it before collection, because routine retention will otherwise delete the mailboxes, logs and file versions the case depends on.
4. **IF** the concern is data leaving the organisation **THEN** establish the data-set breadth and destination baseline first; **IF** the concern is sabotage or credential misuse **THEN** branch to integrity and authentication evidence instead, since the relevant artefact classes differ.
5. **IF** HR intends to act on the findings **THEN** the technical report must distinguish observed facts from inference in separate sections, because a disciplinary decision built on an unlabelled inference is the most common way these cases fail.
6. **IF** telemetry source covering `access pattern` / `hr coordination` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `insider-threat-investigation` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need evidence preservation standard | [`evidence-handling-and-chain-of-custody`](../evidence-handling-and-chain-of-custody/SKILL.md) | Acquisition order, hashing and custody for a disciplinary proceeding |
| Need to scope whether an external actor is involved | [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) | Distinguishing compromised-account activity from subject activity |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for baseline deviation and hold attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Read-only collection and DLP review entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the legal and policy basis before the first query.** Establish the jurisdictional basis for monitoring, the notice position and its acknowledgement record, the scope of what may be examined, and who authorised the investigation. An investigation opened without this basis may produce findings that cannot be acted on, and reopening it later does not restore the destroyed evidence.
2. **Choose the branch by alleged conduct.** Data exfiltration, sabotage or integrity damage, credential or access misuse, and policy violation each need different evidence classes and different corroboration. Choosing late means collecting the wrong artefacts first and the right ones after retention has expired.
3. **Build the subject's own baseline, not a peer baseline.** Establish the subject's normal file-access breadth, download and upload volume, working hours, device usage and destinations over a period before the concern arose. The peer comparison is useful context; the finding is a deviation from the subject's own history, because roles legitimately differ in breadth.
4. **State the stop condition.** Stop when the alleged conduct is either evidenced with attributable artefacts or the relevant sources are exhausted, and when every inference in the report is labelled as inference. Continue only if new evidence changes the branch; repeating the same queries produces more confirmation, not more certainty.
5. **Prove with attributable artefacts and a stated limit.** The proof is an artefact that identifies the subject's principal, the resource, the time and the action, drawn from a source whose coverage is stated. A finding that cannot name its source, its window and its coverage cannot survive the first challenge from a representative, and the honest alternative is to label it as inference.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| File-access count and distinct-document breadth per user compared with that user's own prior period | DLP or file-server audit log | Deviation in data-set breadth, which is the strongest single indicator of collection behaviour before departure |
| Upload destination and volume outside the subject's historical destination set | Proxy or CASB log with destination field | Egress to a place this person has never sent data, which is the destination claim the case rests on |
| Removable-media mount with file-copy events inside the same session | Endpoint USB and file-write telemetry | Physical exfiltration with the device identified and the volume bounded |
| Print, screenshot or clipboard activity volume against the subject's own baseline | Endpoint DLP event stream | Collection by channels that leave the network untouched, which proxy logs cannot show |
| Legal hold record naming the custodian, categories and systems with suspended deletion | Hold record and retention configuration | That evidence was preserved deliberately, and where deletion could not be suspended |
| Access outside the subject's normal working hours joined to a resource they do not normally touch | Authentication log plus resource audit | Timing and targeting deviation together, which is far stronger than either alone |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`access pattern`):**

```text
# ANTI-PATTERN: alert on "downloaded more than 500 files today".
# A new starter onboarding, a project migration and a departing employee
# all trip it. The analyst reviews the subject's whole file history with no
# baseline, finds volume, and reports "unusual access" to HR - who cannot
# act on a comparison that was never made.
```

**Behavior-Anchored Detection & Guarded Triage (`access pattern` — CWE-778):**

```sql
-- Subject-relative deviation: each user is measured against their own history,
-- and the report carries the source, window and coverage with the finding.
WITH prior AS (
  SELECT principal, date_trunc('week', ts) AS wk,
         count(*) AS reads, count(DISTINCT object_id) AS breadth
  FROM file_audit
  WHERE ts BETWEEN now() - interval '180 days' AND now() - interval '21 days'
  GROUP BY 1, 2
),
baseline AS (
  SELECT principal, avg(reads) AS mu_reads, stddev(reads) AS sd_reads,
         avg(breadth) AS mu_breadth
  FROM prior GROUP BY 1
),
probe AS (
  SELECT principal, count(*) AS reads, count(DISTINCT object_id) AS breadth
  FROM file_audit
  WHERE ts > now() - interval '7 days'
  GROUP BY 1
)
SELECT p.principal, p.reads, b.mu_reads, p.breadth, b.mu_breadth,
       round((p.breadth / nullif(b.mu_breadth, 0))::numeric, 2) AS breadth_ratio
FROM probe p JOIN baseline b USING (principal)
WHERE b.sd_reads IS NOT NULL
  AND p.breadth > b.mu_breadth * 3
  AND p.reads   > b.mu_reads + (3 * b.sd_reads)
ORDER BY breadth_ratio DESC;
```

**Why this matters:** Pairs `access pattern` with `hr coordination` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **Onboarding, role change or project migration:** a new responsibility legitimately triples document breadth for a period. Check the HR record and the project assignment before treating breadth as collection.
- **Departing-employee knowledge transfer:** the last weeks of employment involve unusual access to hand over work. The discriminator is destination and timing, not volume.
- **Automation running under a personal account:** a script or sync client configured with an individual's credentials produces steady, high-volume access that looks like collection. Attribute by user-agent and cadence.
- **Shared or generic accounts:** access logs attributed to a shared principal cannot identify a person, and reporting them as a subject's activity is unsupportable. Establish attribution before naming anyone.
- **Compliance, audit or legal-hold review work:** an authorised review legitimately opens large document sets. Confirm the mandate and the reviewer's role before scoring breadth.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `access pattern` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Legal and policy basis documented:** jurisdictional basis, notice position and acknowledgement, scope limits and authorising role are recorded before the first collection query.
- [ ] **Hold applied where it deletes:** the hold names custodians, categories, systems and date range, and the retention configuration shows deletion suspended — or the systems where it could not be are named.
- [ ] **Subject baseline built:** the subject's own prior-period breadth, volume, hours, devices and destinations were measured, and the finding is a deviation from that history.
- [ ] **HR and legal sequenced:** HR engagement follows the legal gate, with the threshold crossing recorded rather than implied.
- [ ] **Fact and inference separated:** the report distinguishes attributable artefacts from interpretation, and each artefact names its principal, resource, time and coverage.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: insider-threat-investigation
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `insider-threat-investigation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/go_exploitdb (4), CYBER_CPT/L5/ctf_search (2), SecEval/windows_security (1), SecEval/d3fend (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
