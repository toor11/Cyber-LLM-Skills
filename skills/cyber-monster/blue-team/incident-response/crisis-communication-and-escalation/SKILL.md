---
name: crisis-communication-and-escalation
description: "Manages incident communication: escalation paths, stakeholder updates, external notification coordination and message discipline. Use during a significant or public incident."
family: incident-response
tier: leaf
triggers: ["incident communication", "crisis escalation", "stakeholder update"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Crisis Communication and Escalation - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Incident communication fails in a specific, repeatable way: statements are issued before the underlying fact has an evidence class attached, and each statement becomes a commitment that later contradicts the next one. The mechanism is structural rather than personal. During an incident, three clocks run simultaneously and are set by different authorities. The operational clock is measured in minutes and governs containment. The evidence clock is measured in hours and governs when a claim becomes defensible. The obligation clock is set by external regimes and is not negotiable: the SEC materiality-based Form 8-K timeline starts at the determination that an incident is material rather than at discovery, NIS2 requires an early warning within 24 hours of awareness and an incident notification within 72 hours, and Australia's SOCI Act sets 12 hours for a critical cyber security incident. A statement issued on the operational clock to satisfy an obligation clock, without the evidence clock having run, is how organisations end up correcting themselves publicly. The precondition that makes communication containable is a single maintained fact register — one line per claim, each with its evidence state (confirmed, unverified, disproven), its source, its timestamp and its owner. Every external statement is then an extraction from that register, and every correction is traceable to a register change rather than to a person's memory.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the communication is internal escalation **THEN** send the fact register extract with evidence states rather than a narrative; **IF** the communication is external **THEN** require that every claim in it carries a `confirmed` state in the register, and remove or qualify everything else.
2. **IF** a regulatory or contractual clock is running **THEN** identify which authority starts it — awareness, discovery, or materiality determination — because the three produce very different deadlines for the same event, and document the chosen interpretation.
3. **IF** law enforcement engagement is being considered **THEN** decide before the first external statement; the decision changes what may be said and when, and reversing it after publication is not possible.
4. **IF** the incident involves personal data **THEN** route the notification decision to legal early, since the assessment window runs in parallel with containment and cannot be reconstructed afterwards.
5. **IF** the audience includes customers, patients or safety-affecting users **THEN** prioritise the action they must take over the description of what happened, and issue the actionable part first.
6. **IF** telemetry source covering `escalation path` / `update cadence` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `crisis-communication-and-escalation` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for notification and statement attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Communication-channel and record-keeping entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm which obligation clocks are actually running, and from what trigger.** Enumerate the regimes that apply by entity type, jurisdiction and contract; for each, record the trigger event, the deadline and who owns the filing. A clock whose trigger has not been identified cannot be met, and a deadline met against the wrong trigger is worse than a late one because it was avoidable.
2. **Choose the branch: internal escalation, external obligation, or public statement.** Each has a different approval authority and a different evidence threshold. Internal escalation tolerates `unverified` items with labels; external obligations tolerate only `confirmed` items; public statements additionally require that the wording survive being quoted out of context.
3. **Build the baseline the statements are judged against.** Establish what was publicly known before the incident, what the organisation's normal disclosure cadence is, and what has already been said to each audience. A statement that contradicts an earlier one without acknowledging the correction reads as concealment, regardless of accuracy.
4. **State the stop condition.** Communication stops when every applicable obligation has a filed record with a timestamp and an owner, every audience has received the final state, and the fact register shows no claim still in `unverified` on a matter that was disclosed. Withdrawing an unverified claim is a communication action, not a documentation one.
5. **Prove each communication by artefact.** The proof is the filed submission receipt or the sent message with its timestamp, the register entry each claim was drawn from, and the approval record naming who authorised it. A statement that was drafted and approved but never sent, or sent without a matching register entry, cannot be defended in review.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Fact-register entry with evidence state, source and owner per claim | Case management record | Which claims are defensible and which are placeholders; every external statement should be traceable to one of these |
| Filing receipt or submission identifier with UTC timestamp per regime | Regulatory submission record | The obligation was met at a specific time by a specific entity, independent of what was later discovered |
| Approval record naming the authorising role for each issued statement | Approval or workflow log | Who committed the organisation to the wording, which is the accountability question in every post-incident review |
| Sent-message record to the affected audience with delivery confirmation | Communication platform log | The notification was delivered, not merely authored — the distinction regulators and courts ask about |
| Contradiction between two issued statements with no correction on record | Statement diff against the register history | An unreconciled inconsistency that will be discovered in review and read as a deliberate omission |
| Clock-start evidence for the obligation trigger, with the determination timestamp | Determination memo and its audit trail | When the obligation clock started, which is the only defensible answer to a late-filing allegation |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`escalation path`):**

```text
# ANTI-PATTERN: issue a customer notice at hour two because the obligation
# feels urgent, phrased from what the incident channel is saying.
# "No customer data was accessed" goes out while the data-event question is
# still unverified. The correction at hour thirty is the story that survives.
```

**Behavior-Anchored Detection & Guarded Triage (`escalation path` — CWE-778):**

```yaml
title: Verified Behavior Check - crisis-communication-and-escalation
statement_gate:
  internal_escalation:
    permitted_states: [confirmed, unverified, disproven]
    requirement: label every claim with its state
  external_obligation:
    permitted_states: [confirmed]
    requirement: register entry id cited beside each claim before approval
  public_statement:
    permitted_states: [confirmed]
    requirement: prior-statement diff reviewed, correction language agreed
clocks:
  - regime: SEC 8-K Item 1.05
    trigger: materiality determination
    deadline: four business days after the determination
  - regime: NIS2 Art. 23
    trigger: awareness of significant incident
    deadline: early warning within 24 hours, notification within 72 hours
  - regime: Australia SOCI Act s 30BC
    trigger: critical cyber security incident
    deadline: 12 hours
proof:
  - filing receipt or sent record with UTC timestamp
  - register entry id behind each disclosed claim
  - approval record naming the authorising role
telemetry_gap_rule: |
  if the fact register cannot be produced, the statements cannot be attested;
  disposition is INCONCLUSIVE rather than "communicated"
```

**Why this matters:** Pairs `escalation path` with `update cadence` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **A maintenance or degradation notice that reads like an incident:** planned outage communications contain the same language of impact and recovery. Check the change record before treating the notice as evidence of a security event.
- **A third-party or supplier notification about their own incident:** the obligation and the facts belong to the supplier; the recipient's duty is assessment, not disclosure of the supplier's timeline. Confirm which entity is the reporting party.
- **A phishing or brand-impersonation campaign reported by customers:** the customers' reports are the trigger, not a statement about your systems. Verify whether any mailbox or system was actually compromised before escalating to incident communication.
- **A regulator's general inquiry that is not an incident notification:** information requests and examinations follow their own timelines and should not start an incident clock. Confirm with counsel which instrument the request is issued under.
- **An internal test of the notification chain:** a tabletop or notification drill produces approval records, sent records and clock timestamps indistinguishable from a real event in the logs. Confirm against the exercise schedule.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `escalation path` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Obligation map built:** each applicable regime is listed with its trigger event, deadline and owner, and the trigger actually relied on is named with its evidence.
- [ ] **Fact register current:** every claim carries an evidence state, a source, a timestamp and an owner, and no claim marked `unverified` appears in an external statement.
- [ ] **Prior statements reconciled:** the new statement was diffed against what each audience has already been told, and any correction is explicit rather than silent.
- [ ] **Approval recorded:** the authorising role for each statement is named in the record, with the time of approval preceding the time of issue.
- [ ] **Delivery attested:** the sent or filed record with its timestamp exists for each audience and each regime, not just a draft.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: crisis-communication-and-escalation
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `crisis-communication-and-escalation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (2), CYBER_CPT/apple_security (1), CYBER_CPT/hacktricks (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
