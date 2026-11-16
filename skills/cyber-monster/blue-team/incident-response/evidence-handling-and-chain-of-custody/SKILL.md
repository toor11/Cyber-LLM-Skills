---
name: evidence-handling-and-chain-of-custody
description: "Preserves evidence defensibly: acquisition order (volatile first), hashing, custody documentation and storage integrity. Use whenever evidence may support legal or disciplinary action."
family: incident-response
tier: core
triggers: ["chain of custody", "evidence handling", "forensic acquisition order"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Evidence Handling and Chain of Custody - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Evidence handling is the discipline of making a later claim about a machine defensible when the machine is no longer available. Its method comes from a single constraint: every action taken on a system changes it, so the order in which actions are taken determines what survives. That is the origin of the volatility ordering in RFC 3227 — registers and cache, then process and network state, then temporary storage, then disk, then remote logs, then archival media — and of the parallel rule that acquisition is done on a copy with the original protected by a hardware or software write blocker, and analysis is performed only on the copy. NIST SP 800-86 adds the evidentiary requirement that integrity be demonstrated: a message digest computed over the original and the acquired copy, compared, with the log of who handled the evidence and what they did retained alongside. Two preconditions make the whole exercise work. The first is a decision, made before collection, about whether the evidence will be needed for a legal or disciplinary proceeding, because that decision changes the collection method; when it is unclear, the standard practice is to preserve. The second is a contemporaneous record: a chain-of-custody log with unique item identification, the transferring and receiving parties, and timestamps for every transfer. A gap in that record is not a clerical problem — it is the specific thing a challenger attacks, and no amount of technical correctness repairs it afterwards.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence may support a legal, regulatory or disciplinary proceeding **THEN** collect to the evidentiary standard from the outset — write blocker, bit-stream image, digest of source and copy, custody log; **IF** that is genuinely unknown **THEN** preserve to that standard anyway, because the standard cannot be applied retrospectively.
2. **IF** the host is still running and memory state is relevant **THEN** capture memory and live network state before any shutdown; **IF** capturing memory may destabilise a production or safety system **THEN** record the decision not to capture and the reason, so the omission is documented rather than discovered.
3. **IF** the subject of the investigation is an employee or contractor **THEN** confirm with legal and HR before collection begins that the jurisdiction, the monitoring notice and the scope are established; collection without that basis can make otherwise sound evidence unusable.
4. **IF** the evidence is cloud-hosted **THEN** treat provider-held logs and customer-controlled copies as different evidentiary classes, and preserve both; a provider export and your own snapshot have different custody chains.
5. **IF** a legal hold is in force **THEN** suspend routine retention and deletion for the covered categories before any collection, and record the systems where deletion could not be suspended.
6. **IF** telemetry source covering `order of volatility` / `hash` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `evidence-handling-and-chain-of-custody` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for integrity and custody attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Acquisition, hashing and verification entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the collection authority and standard before touching the system.** Name who authorised the collection, what proceeding it may support, and therefore which standard applies. A collection begun before this is decided has already chosen a standard by default, and it is the weaker one.
2. **Choose the acquisition branch by evidence class.** Live-system volatile capture, powered-off disk imaging, cloud snapshot, network capture, and log export each have a different original, a different copy mechanism, and a different integrity check. Name the branch and the artefact identity before starting.
3. **Establish the baseline that makes the collection verifiable.** Record the source media identity, size, and any pre-existing damage; record the tool and version used; record the tool's own log and any read errors. Without this baseline, a digest mismatch later cannot be attributed to the media, the tool, or the handler.
4. **State the stop condition.** Stop when every selected artefact has an original, a verified copy, a digest of both, and a custody entry; when every deviation (unreadable sector, agent gap, refused capture) is recorded with its cause; and when the analysis environment is separated from the collection environment.
5. **Prove integrity, and prove handling.** The proof of integrity is a digest computed over the acquired stream and over the copy, compared and recorded, plus a re-verification at each later access. The proof of handling is the custody log with item identity, transferring and receiving party, and timestamps. Neither substitutes for the other: an intact hash with an incomplete log is challengeable, and a perfect log over a modified image is worth nothing.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Source digest and copy digest recorded side by side at acquisition time | Acquisition log | Integrity of the copy relative to the source at the moment of acquisition, which is the baseline every later verification is measured against |
| Write-blocker identity and firmware or version in the acquisition record | Tooling record | That the source was not written to, which is the specific allegation a defence raises first |
| Custody entry with item id, transferring party, receiving party, and both timestamps | Chain-of-custody log | Who held the evidence and when; gaps here are what makes technically sound work inadmissible |
| Re-verification digest at each access, later than acquisition | Access log | That the copy is unchanged across the whole period, not only at the start |
| Acquisition tool log including read errors and skipped regions | Tool output | Which parts of the media were never readable, so no later claim implies completeness it does not have |
| Legal hold notice with custodian scope, date range and suspended systems | Hold record | That deletion was suspended deliberately for named categories, and where it was not |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK PRACTICE:
copy the suspect files to a share, zip them, email the zip to legal.
# No source digest, no write blocker, no custody entry.
# Every metadata field the copy preserved is now arguable, and the
# "when did you take this" question has no answer better than a memory.
```

**High-Signal Grounded Artifact:**

```powershell
# Evidentiary-shaped acquisition record: identity, tooling, digests, errors.
$case   = 'INC-2026-1114'
$item   = 'FS-01-system-volume'
$source = '\\\\.\\PhysicalDrive1'
$dest   = "D:\evidence\$case\$item.dd"
$log    = "D:\evidence\$case\$item.acquisition.json"

$tool = Get-Command dc3dd -ErrorAction SilentlyContinue
if (-not $tool) { throw 'acquisition tool not present; record the gap rather than substituting' }

$started = (Get-Date).ToUniversalTime().ToString('o')
# Acquisition itself is run out-of-band with the write blocker attached;
# this record documents what was done and captures the digests.
$record = [ordered]@{
    case              = $case
    item_id           = $item
    source_device     = $source
    write_blocker     = $env:WRITE_BLOCKER_MODEL
    tool              = 'dc3dd'
    tool_version      = (& dc3dd --version 2>&1 | Select-Object -First 1)
    started_utc       = $started
    source_sha256     = $env:SOURCE_SHA256
    copy_sha256       = (Get-FileHash -Algorithm SHA256 -Path $dest).Hash
    read_errors       = $env:READ_ERRORS
    acquired_by       = $env:ACQUIRED_BY
    verified_by       = $env:VERIFIED_BY
}
$record | ConvertTo-Json -Depth 3 | Out-File $log -Encoding utf8

if ($record.source_sha256 -ne $record.copy_sha256) {
    Write-Warning 'digest mismatch recorded as a deviation, not silently corrected'
}
```

**Why this matters:** Non-destructive verification check; compare against baseline.

## When It Is NOT This Issue

- **Routine operational logging collected for monitoring:** telemetry retained for detection has a different legal character from evidence collected for a proceeding. Treating the log platform as an evidence store without a hold in place means retention will delete it on schedule.
- **A vendor's own forensic report:** the vendor's custody chain covers their handling, not yours. Relying on their hash without your own verified copy leaves a gap in your record that you cannot close afterwards.
- **A system image taken for rebuild rather than for evidence:** a deployment or backup image is not an acquisition, has no source digest, and may have been modified by the restore process. Do not present one as the other.
- **Screenshots and notes as the only record:** these are useful corroboration and are not evidence of system state; they carry no integrity attestation and no custody chain.
- **A cloud snapshot taken without a legal hold:** the snapshot proves storage state at a moment, not that retention was suspended; provider-side lifecycle rules can still expire the underlying data.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `order of volatility` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Authority and standard recorded:** who authorised collection, what proceeding it may support, and therefore which evidentiary standard applied, decided before the first action.
- [ ] **Volatility order observed:** memory, live network state and process state were captured before shutdown or isolation where relevant, and any deliberate omission is documented with its reason.
- [ ] **Original protected:** a write blocker or equivalent was used, and its identity is recorded; analysis was performed on a copy, not the original.
- [ ] **Integrity demonstrated:** source and copy digests were computed and compared at acquisition, with read errors and unreadable regions recorded rather than omitted.
- [ ] **Custody continuous:** every item has an entry with unique identification, transferring and receiving parties, and timestamps, with no unexplained interval.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: evidence-handling-and-chain-of-custody
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `evidence-handling-and-chain-of-custody` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/ctf_search (14), CYBER_CPT/github_security_md (3), CYBER_CPT/ctf_wiki (2), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
