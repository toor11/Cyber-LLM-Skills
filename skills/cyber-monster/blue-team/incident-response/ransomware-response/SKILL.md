---
name: ransomware-response
description: "Responds to ransomware: early containment, identifying the strain and entry vector, backup and recovery assessment, negotiation and regulatory considerations. Use when ransomware is detected or suspected."
family: incident-response
tier: flagship
triggers: ["ransomware response", "ransomware attack", "locked files", "encryption event"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ransomware-response-containment-and-scoping, ransomware-response-recovery-and-restore, ransomware-response-strain-and-actor-identification, incident-response-playbooks]
---

# Ransomware Response - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **flagship** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Ransomware is the last act of an intrusion that has usually been running for days: an entry through an internet-facing appliance, a stolen credential or a delivered loader, then privilege escalation, discovery, credential access, archive creation and outbound transfer, and only then encryption. That sequence is what makes the class containable at all — the destructive step leaves an enormous, unambiguous artifact trail, and every stage before it leaves a smaller one. Victim-side response therefore proceeds on two clocks at once: the short clock that stops encryption and preserves the decryptable evidence, and the long clock that establishes what was taken before encryption began, because a double-extortion claim turns a recovery problem into a disclosure and notification problem. The precondition is immutable, physically separated backups that were tested before the incident; if the only copies are reachable from the compromised credentials, no response method recovers the data. CISA's #StopRansomware Guide (September 2023, republished March 2025) and the current #StopRansomware advisories — Medusa (AA25-071A), Gunra (AA26-222A), SafePay (AA26-293A) — all converge on the same three preconditions: patched internet-facing systems, network segmentation, and offline immutable backups in a separate segmented location.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves containment breadth, staging hosts or re-entry **THEN** switch to [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) (1 hop).
2. **IF** the target specifically involves backup validation, restore order or proving the vector closed **THEN** switch to [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) (1 hop).
3. **IF** the target specifically involves naming the family from artifacts or notes **THEN** switch to [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) (1 hop).
4. **IF** the claim includes stolen data as well as encrypted data **THEN** treat it as double extortion and route the outbound-transfer question to [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md); do not let the encryption timeline stand in for the exfiltration timeline.
5. **IF** the earliest confirmed artifact is an identity event — a successful VPN or webmail sign-in, a new MFA method, a token grant — **THEN** take the identity-first branch: revoke sessions before touching hosts, because an isolated host with a live refresh token is not contained.
6. **IF** the earliest confirmed artifact is on an internet-facing appliance — an auth-bypass request, a management-interface login from an untrusted source, a new local account on the appliance — **THEN** take the edge-first branch: preserve the appliance configuration and logs before any firmware change, then work inward.
7. **IF** encryption is still spreading when the first responder arrives **THEN** prioritise stopping spread over completeness of capture: isolate at the segment boundary, not host by host, and accept that per-host memory capture will be partial and must be recorded as partial.
8. **IF** a legal hold, regulatory clock or insurer engagement attaches **THEN** decide hold-before-containment explicitly and record the decision; a hold does not forbid isolation, it forbids destruction of the artifacts you will need to date the obligation.
9. **IF** telemetry covering the encryption window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
10. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `ransomware-response-containment-and-scoping` | [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) | Blast radius, isolation order, re-entry validation |
| Target matches `ransomware-response-recovery-and-restore` | [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) | Immutable backup validation and restore sequencing |
| Target matches `ransomware-response-strain-and-actor-identification` | [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) | Family and note-structure identification for reporting |
| Data appears to have left the estate | [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) | Exfiltration attestation and disclosure routing |
| Need the evidence classes and attestation queries | [`QUERIES.md`](QUERIES.md) | Onset clock, entry-vector branch, sabotage signals |
| Need exact collection and read-only verification flags | [`TOOLS.md`](TOOLS.md) | Collection, EVTX timeline, memory and share enumeration |
| Need the operational decision matrix | [`PLAYBOOK.md`](PLAYBOOK.md) | Sequencing, authority and hold decisions |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the evidence source before naming the incident.** Enumerate what exists for the affected segments — endpoint file and process telemetry, file-server and hypervisor logs, identity-provider audit, VPN and edge-appliance logs, backup job history — and check whether each was collecting during the window. The single most common wrong answer in this class is a timeline built on endpoint telemetry from a segment whose agent was pushed off days earlier.
2. **Choose the branch from the earliest corroborated artifact.** Edge-first when an appliance or VPN event precedes everything; identity-first when a successful sign-in with a new session precedes everything; endpoint-first when a delivered loader or new service is the earliest artifact. State the branch, because it decides whether containment starts with tokens or with hosts.
3. **Define the baseline-and-probe differential that separates encryption from ordinary bulk change.** Compare files-written-per-minute per host against that host's own prior 14 days, and compare new file extensions across the estate against the pre-incident extension inventory. Encryption is a sustained write burst plus a previously unseen extension; a backup job or a content migration produces the burst without the new extension, and an antivirus quarantine produces neither.
4. **Bound the decision window and name the stop condition.** Record the first and last observed encryption write per host. Stop and declare `Inconclusive` on scope when a segment has no agent coverage and no file-server audit, when the shadow-copy and backup service logs were cleared, or when the only evidence of exfiltration is the actor's own claim. Do not let an actor's assertion become a fact in your own report.
5. **State what counts as proof.** Proof of encryption is a file whose current content and extension differ from a known-good copy, corroborated by a write event on a monitored host. Proof of exfiltration is destination-side or metadata-side confirmation — a completed transfer recorded by a proxy, firewall or cloud audit log, or a manifest of files that demonstrably left — not a large outbound byte count. Proof of containment is a verified absence of new encryption writes after the isolation timestamp, not the issuance of an isolation command.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Sustained file-write burst plus a previously unseen extension per host | file telemetry | Encryption occurred here, and the first write bounds the onset for that host |
| Shadow-copy deletion, backup service stop or recovery-agent tamper before the burst | control-plane artifact | Preparation, not impact; the deletion timestamp is the strongest pre-impact anchor available |
| Note file with a consistent name and structure across hosts | artifact | One operator and one deployment, which supports a single incident rather than parallel unrelated events |
| New local account or MFA method on a VPN or edge appliance inside the window | appliance and identity audit | The entry vector, which decides whether containment begins with credentials or hosts |
| Proxy or firewall record of a completed large transfer hours before the burst | network egress | Data left before encryption; supports a disclosure question, not a payment decision |
| Backup job success and immutability state for the last pre-incident run | backup control plane | Whether recovery is possible without the actor, which governs the whole decision set |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```powershell
# WEAK: "files changed a lot, therefore ransomware"
# A single write-volume threshold with no extension baseline, no per-host history,
# and no check that the file-server audit log was even enabled for the share.
Get-ChildItem -Path D:\ -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) }
```

**High-Signal Grounded Artifact:**

```powershell
# Scope the onset per host, against each host's own history, and record the gap explicitly.
$since = (Get-Date).AddDays(-14)
$probe = Get-Date "2026-11-14T02:00:00Z"

# 1. Extension inventory: what existed before the incident?
$baseline = Get-ChildItem -Path D:\Shares -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $probe } |
    Group-Object Extension | Select-Object Name, Count

# 2. Extensions that only appear inside the probe window are candidates, not conclusions.
$new = Get-ChildItem -Path D:\Shares -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $probe } |
    Group-Object Extension | Select-Object Name, Count

$new | Where-Object { $_.Name -notin $baseline.Name } |
    Export-Csv -NoTypeInformation -Path .\candidate-extensions.csv

# 3. State coverage before interpreting: audit policy on the share, agent state, log retention.
auditpol /get /category:"Object Access"
```

**Why this matters:** the strong form derives the suspicious extension set from the estate's own prior inventory and refuses to interpret the result until file-access auditing and agent state are confirmed, so a burst from a backup job and a burst from encryption are told apart by evidence rather than by volume; the weak form reports every recently written file and calls the largest group an incident.

## When It Is NOT This Issue

- **Backup, deduplication or migration job:** a content migration, an index rebuild or a snapshot consolidation produces a massive sustained write burst across many hosts with no new extension and no note. Check the job scheduler for the same window before scoping anything.
- **Antivirus or EDR quarantine sweep:** a signature update quarantining a widely deployed legitimate binary renames files en masse, and the quarantine action log — not the file system — is the artifact that explains it.
- **Storage or filesystem fault:** a failing volume, a full datastore or a corrupted deduplication store produces unreadable files and angry users, and no actor artifact exists at all. Look for hardware and hypervisor events before assuming intent.
- **Rogue administrator or scripted bulk rename:** an intern's batch rename, a scripted archival policy or a misconfigured sync client renames files without encrypting them; open a sample and check whether the content is recoverable.
- **Note file without encryption:** a hoax, an insurance-fraud attempt or a leftover artifact from a previous incident can place a note with no encryption and no access. A note is a claim; the file state is the evidence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is clean when telemetry covering the encryption window was disabled, rotated out, or uncollected.**
- **NEVER restate an actor's claim of exfiltration as a confirmed finding** — label it as an unverified claim until destination-side or manifest evidence exists.
- **NEVER present an isolation command as containment** — containment is verified absence of new writes after the isolation timestamp.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Coverage confirmed per segment:** every segment in scope has at least one collection path, and segments without one are declared out of scope rather than assumed clean.
- [ ] **Branch stated:** edge-first, identity-first or endpoint-first was chosen from the earliest corroborated artifact and named in the output.
- [ ] **Differential defined:** the write burst was compared against the host's own baseline and against the estate extension inventory, not against a fixed threshold.
- [ ] **Backup recoverability checked:** the last pre-incident backup's success, separation and immutability state were verified read-only before any recovery claim.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ransomware-response
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) - Incident Response (leaf)
- [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) - Incident Response (leaf)
- [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ransomware-response` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Victim-side scope:** this skill covers scoping, preservation, recovery and disclosure decisions only. Negotiation, payment and actor-communication content is explicitly out of scope and routes to counsel, the insurer and law enforcement.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 9 |
| Top sources | cyber-security/CyberSec-Dataset (4), CYBER_CPT/ctf_search (4), SecEval/attck (1), SecEval/d3fend (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
