---
name: legal-and-regulatory-notification
description: "Handles legal and regulatory obligations after an incident: breach notification thresholds, timelines, regulator and customer communication, and counsel coordination. Use when an incident may trigger disclosure duties."
family: incident-response
tier: leaf
triggers: ["breach notification", "regulatory notification", "gdpr breach", "legal obligation"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Legal and Regulatory Notification - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Notification obligations are not triggered by an incident. They are triggered by a specific event defined slightly differently in every regime: awareness of a personal data breach, classification of an incident as major, a determination that an incident is material. Each definition starts its own clock, and the clocks run concurrently against the same facts. The practical consequence is that the technical work and the legal work must share one timeline, because the SOC's answer to "when were we aware" — a specific minute with a specific artifact behind it — is the input that either starts or stops a statutory clock, and reconstructing that minute after the fact is where organisations get into difficulty. The precondition that makes the process defensible is contemporaneous record-keeping from the first report: who was told, when, what was known, what was unknown, and which decision was made on which evidence. A decision to delay is legitimate when it is documented; an undocumented delay is indistinguishable from a missed deadline.

This skill covers obligation identification, clock analysis, recipient mapping and evidence packaging. It does not give legal advice and does not decide registrability — counsel does. What it does is supply counsel with the dated, sourced facts they need.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the incident involves personal data of EU or UK data subjects **THEN** the GDPR-style clock is the tightest binding constraint — supervisory authority notification without undue delay and no later than 72 hours from awareness — and awareness is an evidence question, not a feeling.
2. **IF** the entity is an EU financial entity or an ICT third-party provider to one **THEN** DORA's cadence applies instead of NIS2: initial notification within four hours of classifying an incident as major and no later than 24 hours from awareness, intermediate report within 72 hours of the initial, final report within one month of the last intermediate.
3. **IF** the entity is a US-listed issuer **THEN** the four-business-day Form 8-K Item 1.05 window runs from the materiality determination, and that determination must be made without unreasonable delay after discovery — the clock starts at a decision, but the delay in reaching it is itself reviewable.
4. **IF** the entity is a US bank, insurer or financial-services firm **THEN** check the sector rule separately — the 36-hour computer-security incident notification for banking regulators and the 72-hour NYDFS notification are different clocks from the SEC's and run from different triggers.
5. **IF** the incident is ransomware **THEN** determine whether the applicable regime obliges a report on encryption alone or on the exfiltration claim as well, and route the exfiltration question to [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) rather than guessing.
6. **IF** a regulator, customer or contractual counterparty has a shorter notice obligation than any statute **THEN** the contract governs the operational deadline and is frequently measured in hours; obtain the clause before the first external call is made.
7. **IF** any external communication is contemplated **THEN** establish privilege and the communication owner first; an uncoordinated statement to a customer or regulator becomes a fixed record that later facts must be reconciled against.
8. **IF** telemetry that would establish the awareness timestamp is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` on the clock question — never present an unevidenced timestamp as the start of a statutory period.
9. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the awareness and obligation evidence classes | [`QUERIES.md`](QUERIES.md) | First-report timestamps, decision records, data-scope joins |
| Need read-only audit-export and evidence flags | [`TOOLS.md`](TOOLS.md) | Preserve the awareness timeline in a defensible form |
| Need the decision matrix and escalation sequence | [`PLAYBOOK.md`](PLAYBOOK.md) | Who is told, when, in what order |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Exfiltration question unresolved | [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) | The factual input the obligation analysis needs |
| Timeline provenance in dispute | [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) | Awareness timestamp must be evidenced |
| Evidence must survive legal scrutiny | [`evidence-handling-and-chain-of-custody`](../evidence-handling-and-chain-of-custody/SKILL.md) | Hash, custody and storage integrity |
| External messaging discipline | [`crisis-communication-and-escalation`](../crisis-communication-and-escalation/SKILL.md) | Statement ownership and cadence |

## Procedure

1. **Confirm the evidence source for the awareness timestamp before any clock is asserted.** Enumerate the report path: the first alert timestamp in the detection platform, the ticket creation time, the first human acknowledgement, the first escalation message, and the first time a decision-maker was informed. These are five different moments and different regimes key off different ones. Record all five with their source and whether each is confirmed or inferred.
2. **Choose the branch from the entity's regulatory footprint, not from the incident's severity.** Financial-entity branch (DORA or sector banking rules), listed-issuer branch (SEC materiality), personal-data branch (GDPR-style 72 hours), and contractual branch (customer and vendor clauses) run in parallel. A single incident can start three clocks with three different durations.
3. **Define the data-scope differential that answers "is this a personal data breach".** Join the affected systems against the record-of-processing inventory and the data-classification catalogue, and compare against the same join for a comparable, unaffected system. The differential tells you whether the incident touched a category that carries an obligation, which is a narrower and more answerable question than "was data taken".
4. **Bound the clock analysis and name the stop condition.** State the earliest defensible awareness moment, the latest defensible one, and the resulting deadline range under each regime. Stop and declare `Inconclusive` when the first-report artifact is missing or was deleted, when the decision record for the materiality determination does not exist, when the data-scope join depends on an inventory that is known incomplete, or when the contract text has not been obtained.
5. **State what counts as proof.** Proof of awareness is a timestamped artifact — alert record, ticket creation, immutable chat log — corroborated by the person who received it. Proof that an obligation applies is a classification join showing the affected data category, or an explicit counsel determination. Proof that a decision was made is a dated record naming the decision, the evidence considered and the owner. A recollection in a meeting is none of these.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| First alert or ticket timestamp with its platform record ID | detection record | The earliest defensible awareness moment, which is the clock start in most regimes |
| Escalation message to a decision-maker, with timestamp and recipients | communication record | When the organisation could first act; supports an argument about the determination delay |
| Materiality determination record with evidence considered | governance record | That a decision was made without unreasonable delay, or that no such record exists |
| Data-classification join showing affected category | classification record | Whether the incident touched data that carries a statutory or contractual obligation |
| Contract clause with a customer notification deadline in hours | contractual record | The tightest operational deadline, which frequently precedes any statutory one |
| Regulator acknowledgement or submission receipt | external record | The obligation was discharged, with the actual submission time rather than the intended one |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: the notification decision is reconstructed from memory, after the fact.
"Team believes the alert came in Tuesday morning; 72h window probably started then.
 We'll file by Friday if legal agrees."
```

**High-Signal Grounded Artifact:**

```text
AWARENESS TIMELINE - case IR-2026-0417 (all times UTC, source-linked)

T0  2026-11-10 04:12:07  EDR alert fired            src: platform alert ID 88f2...
T1  2026-11-10 04:19:44  SOC ticket created         src: ticket 41207, creation field
T2  2026-11-10 05:02:10  Analyst acknowledgement    src: ticket first comment, author
T3  2026-11-10 06:41:00  Escalated to CISO           src: incident bridge invite, accepted
T4  2026-11-10 09:15:00  Counsel engaged            src: engagement email, timestamped

CLOCK ANALYSIS (counsel to confirm applicability)
  GDPR-style 72h from awareness (T1 or T2) -> deadline 2026-11-13 04:19 or 05:02
  Contractual customer notice (24h from confirmed compromise) -> deadline 2026-11-11 T3+24h
  SEC 8-K 4 business days from materiality determination -> determination record: NOT YET MADE

OPEN / INCONCLUSIVE
  - No record located for the materiality determination; cannot assert a start date.
  - Data-scope join depends on inventory last refreshed 2026-09-30; treated as partial.
```

**Why this matters:** the strong form separates the five distinct moments that different regimes key off, attaches a source identifier to each, and states plainly which clock cannot be started because a decision record does not exist; the weak form collapses everything into one remembered time and turns an evidentiary problem into a scheduling guess.

## When It Is NOT This Issue

- **A near-miss with no data access:** a blocked intrusion, a quarantined phish with no click, or a failed exploit attempt may generate an incident record without triggering any notification duty. Establish whether any data category was actually reached before invoking the obligation workflow.
- **An incident already notified by a processor:** a vendor incident the vendor has already reported under its own obligations does not automatically require a separate controller notification, but the controller's own assessment duty usually survives. Read the contract and the vendor's notice before deciding.
- **A clock that has not started despite an incident:** awareness of an incident and awareness of a personal data breach are different events in most regimes. An incident with no personal-data involvement may start no clock at all, and an over-eager notification carries its own consequences.
- **A contractual deadline mistaken for a statutory one:** customer contracts often impose 24-hour notice that is stricter than any regulation. Treating the statutory deadline as the operational one is a breach of contract even when the regulator is satisfied.
- **A regulator's information request that is not a notification duty:** a supervisory enquiry, a sector survey or a threat-intel request arrives with its own response deadline and is not the same obligation as a breach notification. Route it to the correct owner rather than through the breach workflow.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER state a statutory deadline as settled law** — present the calculated range, cite the regime, and mark the applicability determination as counsel's.
- **NEVER assert an awareness timestamp that has no timestamped artifact behind it**, and never present an inferred time as the start of a statutory period.
- **NEVER conclude a data category was unaffected when the classification inventory covering it is known to be incomplete** — say the answer is open.
- **NEVER draft or send external statements from this skill** — communication ownership belongs to crisis communication and counsel.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Awareness evidenced:** every candidate awareness moment has a timestamped source identifier, and inferred times are marked as inferred.
- [ ] **Regimes mapped:** each potentially applicable regime was named with its trigger event and deadline, and applicability is marked as counsel's determination rather than the SOC's.
- [ ] **Data scope joined:** the affected systems were joined against a classification or processing record, and the inventory's freshness is stated.
- [ ] **Decision records located or reported missing:** the materiality or classification determination exists and is dated, or its absence is explicitly reported.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: legal-and-regulatory-notification
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
- [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) - Incident Response (core)
- [`crisis-communication-and-escalation`](../crisis-communication-and-escalation/SKILL.md) - Incident Response (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `legal-and-regulatory-notification` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Not legal advice:** this skill assembles dated, sourced facts for counsel. Applicability, privilege and the notification decision belong to counsel and the executive owner.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/expku (4), cyber-security/CyberSec-Dataset (2), CYBER_CPT/oxdf (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
