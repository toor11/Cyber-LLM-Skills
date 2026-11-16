---
name: raas-extortion-and-negotiation-triage
description: "Handles double/triple-extortion Ransomware-as-a-Service (RaaS) incidents: data-exfiltration volume confirmation from egress/cloud logs, OFAC/sanctions legal screening before any communication, proof-of-life/decryption test-file hygiene, and leak-site data impact scoping. Use during extortion-phase ransomware response."
family: incident-response
tier: core
triggers: ["raas extortion", "double extortion response", "ofac ransomware check", "data exfiltration scoping"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
corpus_sparse: true
---

# RAAS Extortion and Negotiation Triage - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Double extortion changes the shape of a ransomware incident from a recovery problem into a disclosure problem. The operator's leverage is not the encryption — backups usually answer that — but the claim that regulated, customer or employee data has already left the estate. That claim is made before encryption and is therefore almost never visible in the artifacts responders reach for first; the evidence that resolves it lives in egress telemetry, object-storage audit logs, mail-flow logs and data-classification records, and it resolves to one of exactly three answers: transferred and sensitive, transferred and not sensitive, or no completion record at all. The precondition that makes this class tractable is disciplined separation of the three questions — what left, what obligation it creates, and who has authority to decide — because organisations that collapse them into a single meeting end up making a disclosure decision on an unproven egress claim, or delaying a required notification while chasing proof they will never get.

This skill covers victim-side scoping, evidence preservation, obligation routing and decision authority. It does not cover communication with an actor, payment mechanics, extortion-amount reasoning or negotiation strategy; those decisions belong to counsel, the cyber insurer and law enforcement, and the record of them is held outside this library.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the claim asserts data theft as well as encryption **THEN** open two parallel workstreams — recovery scoping and exfiltration attestation — and refuse to let either's timeline stand in for the other's.
2. **IF** the operator claims exfiltration but no egress completion record exists **THEN** record the claim as unverified and route the disclosure decision to counsel with that label intact; absence of evidence is not evidence of absence, and it is also not proof of theft.
3. **IF** egress telemetry is missing for the pre-encryption window — no proxy, no flow, no cloud audit **THEN** report `INCONCLUSIVE (Telemetry Gap)` on the exfiltration question and say so in the disclosure record. Never resolve it as `no exfiltration`.
4. **IF** the estate holds regulated data — health, financial, personal, or government-marked — **THEN** take the obligation-first branch and establish the notification clocks before containment is finished, because some clocks start at awareness, not at confirmation.
5. **IF** any actor identifier, wallet address or infrastructure indicator is available **THEN** hand it to counsel and the insurer for sanctions screening as a named, documented step; do not perform or record that analysis as a technical finding.
6. **IF** law-enforcement engagement is available **THEN** treat it as a decision with a timestamp and an owner, not a background task; it is a documented mitigating factor in sanctions guidance and it may unlock decryption or attribution support.
7. **IF** a legal hold is being considered **THEN** decide explicitly whether hold precedes containment and record the reasoning; hold obliges preservation of the artifacts that date the obligation, it does not forbid isolation.
8. **IF** the operator publishes a leak-site entry **THEN** scope what data it references against internal classification records — for the notification decision only. Do not access, download or interact with the site from corporate infrastructure.
9. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the egress and obligation evidence classes | [`QUERIES.md`](QUERIES.md) | Completion records, staging manifests, classification joins |
| Need read-only egress and object-store inspection flags | [`TOOLS.md`](TOOLS.md) | Confirm transfers without alerting or altering them |
| Need the decision matrix and escalation routing | [`PLAYBOOK.md`](PLAYBOOK.md) | Authority, clocks and who decides what |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Encryption still advancing | [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) | Containment breadth precedes the obligation analysis |
| Need obligation clocks and regulator routing | [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) | Notification thresholds, timelines and recipient set |
| Need the family's documented behaviour | [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) | Reputation tells you where to look, not what happened |

## Procedure

1. **Confirm the evidence source for the egress question before interpreting any claim.** Enumerate which telemetry could prove a transfer: proxy and next-gen firewall logs with byte counts and completion status, cloud object-storage audit logs, mail-flow logs, DLP alerts, network flow records, and staging-directory filesystem history. State which of these existed for the pre-encryption window; a missing plane caps the achievable confidence and must be declared, not smoothed over.
2. **Choose the branch from what the evidence supports.** Completion-record branch when a transfer is recorded with a destination and a size — the question becomes what was in it. Manifest branch when staging artifacts survive but egress telemetry does not — the question becomes what was staged and whether it plausibly left. Claim-only branch when neither exists — the question becomes what obligation attaches to an unverified assertion, which is counsel's question, not the SOC's.
3. **Define the classification join that separates sensitive from non-sensitive.** Join whatever was transferred or staged against the data-classification catalogue and the record-of-processing inventory, by path, repository or application owner. A transfer of build artifacts is a different obligation from a transfer of a patient index; the join, not the byte count, decides which.
4. **Bound the answer and name the stop condition.** State the earliest and latest possible transfer times, the destination set, and the confidence. Stop and declare `Inconclusive` when the decisive plane was absent during the window, when the destination is a sanctioned bulk-egress endpoint whose internal routing cannot be traced, when staged files were deleted before capture, or when the only source is the operator's own statement.
5. **State what counts as proof.** Proof of exfiltration is a completion record — a proxy or firewall log showing the transfer completed with a destination and byte count, or a destination-side object listing — corroborated by a staged manifest or classification join. Proof of data sensitivity is a match against a maintained classification record. A large outbound byte count without a completion record is a lead; an operator's claim is an allegation; neither is proof, and the report must use those words.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Proxy or firewall record of a completed transfer to an unsanctioned destination | network egress | Data left the estate; the destination and size bound the scope of the obligation question |
| Staging directory with archive files named after internal repositories | filesystem artifact | Collection happened and what was collected; supports an inference, not a transfer |
| Cloud object-storage audit entry showing an external principal reading a bucket | data-plane audit | A completed read by an unauthorised principal, which is exfiltration at the data plane |
| Transfer matched against the data-classification catalogue | classification join | Whether the data carries a regulated obligation, which is the actual decision input |
| Missing egress plane for the pre-encryption window | coverage gap | The exfiltration question cannot be resolved from telemetry; declare it, do not fill it |
| Leak-site entry referencing a dataset name that exists in internal inventory | external claim, cross-checked | The claim is specific enough to be assessed; still an allegation until corroborated |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`egress byte volume`):**

```kusto
// ANTI-PATTERN: one big number, no completion status, no destination policy,
// no classification join, and no statement that the egress plane existed at all.
CommonSecurityLog
| where SentBytes > 100000000
| summarize TotalBytes = sum(SentBytes) by SourceIP
```

**Behavior-Anchored Detection & Guarded Triage (`egress byte volume` — CWE-778):**

```kusto
let onset = datetime(2026-11-14T02:00:00Z);
let sanctioned = dynamic(["storage.corp.example", "backup.corp.example"]);
CommonSecurityLog
| where TimeGenerated between (onset - 96h .. onset)
| where DeviceAction in ("allow", "accept")
| extend Dest = coalesce(DestinationHostName, DestinationIP)
| where Dest !in (sanctioned)
| summarize Transfers = count(), Completed = countif(DeviceAction == "allow"),
            Bytes = sum(SentBytes), First = min(TimeGenerated), Last = max(TimeGenerated)
    by Src = SourceIP, Dest, Url = RequestURL
| extend Verdict = case(
    Completed > 0 and Bytes > 10000000, "transfer completed - assess content",
    Completed > 0, "transfer completed - small, assess plausibility",
    "no completion record - claim unverified")
| order by Bytes desc
```

**Why this matters:** the strong form subtracts sanctioned bulk-egress endpoints, keeps the completion status attached to every row, and states a verdict per destination, so a completed transfer to an unknown host and a failed attempt to the same host are never reported as the same finding; the brittle form sums bytes across all destinations and produces a number that supports neither a disclosure decision nor its refusal.

## When It Is NOT This Issue

- **Sanctioned bulk egress:** offsite replication, backup shipping, CDN uploads and developer pushes to approved storage dominate any unfiltered byte-count query. Subtract the sanctioned set before assessing anything, and record the set you used.
- **An operator's claim with no corroboration:** extortion claims are made to create urgency, and some are inflated, copied between victims, or recycled by a different actor. A claim is an input to the obligation analysis, never a finding.
- **A leak-site entry that republishes public data:** a site can list an organisation using already-public material, screenshots of marketing pages or data from an unrelated breach. Cross-check against internal classification before it drives a notification.
- **Internal large transfer:** a data-warehouse load, a migration or an analytics export inside the estate generates the same byte volumes with both endpoints internal. Confirm destination ownership before treating a transfer as external.
- **A disclosure clock that has not started:** awareness of an *incident* is not the same as awareness of a *personal data breach*, and the two start different clocks in different regimes. Let counsel determine which clock applies rather than assuming the earliest.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude data was not exfiltrated when egress, flow or cloud-audit telemetry was absent for the window** — the correct verdict is `Inconclusive (Telemetry Gap)`.
- **NEVER restate an operator's claim of stolen data as a confirmed finding**, and never restate its absence as proof nothing was taken.
- **NEVER provide negotiation strategy, payment mechanics, ransom-amount reasoning, or actor contact details** — route those questions to counsel, the insurer and law enforcement.
- **NEVER access, download from or interact with an actor-operated site from corporate infrastructure.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Egress planes enumerated:** every telemetry source that could prove a transfer was named, and its presence or absence for the pre-encryption window is stated.
- [ ] **Claim labelled:** the operator's assertion is recorded as a claim, separately from evidence, everywhere it appears in the output.
- [ ] **Classification join performed:** transferred or staged content was matched against a maintained classification record, or the absence of such a record is stated.
- [ ] **Routing stated:** each open question names its owner — counsel, insurer, law enforcement, regulator — rather than being left with the SOC.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: raas-extortion-and-negotiation-triage
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
- [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) - Incident Response (leaf)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) - Incident Response (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `raas-extortion-and-negotiation-triage` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Victim-side only:** despite the slug, this file is decision support and escalation routing. It deliberately contains no negotiation tactic, no payment or cryptocurrency guidance, no actor contact path and no ransom-amount reasoning.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope. Never interact with actor infrastructure.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
