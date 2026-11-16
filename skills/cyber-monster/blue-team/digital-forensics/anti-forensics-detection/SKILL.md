---
name: anti-forensics-detection
description: "Detects anti-forensic activity: log manipulation, timestomping, artefact deletion and secure wiping indicators. Use when evidence may have been deliberately altered or destroyed."
family: digital-forensics
tier: core
triggers: ["anti forensics", "timestomping detection", "log tampering detection"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-93]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
corpus_sparse: true
---

# Anti Forensics Detection - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Anti-forensic activity is established from inconsistency and absence, never from a single missing object, and each durable artifact fails in its own way. NTFS carries two independent timestamp sets per record: `$STANDARD_INFORMATION` (attribute 0x10) is writable by any user-mode caller of `SetFileTime`, while `$FILE_NAME` (attribute 0x30) is written by the kernel on create, rename, move and hard-link and is not reachable through that API. Divergence between them — `$SI` born earlier than `$FN` born, or `$SI` truncated to `.0000000` while `$FN` retains natural sub-second digits — is the timestomp signature, and it proves the metadata was rewritten, not who rewrote it. The change journal `$Extend\$UsnJrnl:$J` records the rewrite itself as a `BasicInfoChange` reason, carries a monotonically increasing USN per record, and writes `Close` records holding the timestamps as they stood at handle close; a close record whose timestamp predates an earlier record for the same file reference is a contradiction the tooling cannot repair. Event log clearing writes 1102 into Security and 104 (`Microsoft-Windows-Eventlog`) into System after the wipe, so 1102 or 104 as a channel's oldest surviving record means that channel was refreshed, while a jump in `EventRecordID` with no clear record indicates selective removal by an editor rather than a native clear. None of this describes intent: retention policy, size-based rollover, a channel that was never enabled, and a backup or EDR agent pruning its own log produce the same silhouettes, so every gap must be closed with a second, independently written artifact.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the real question is what an artifact normally means **THEN** settle the normal reading from [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) first; this skill only asks whether that artifact was edited or removed, and a baseline you have not established cannot be shown to have been violated.
2. **IF** the host is still live **THEN** collect in volatility order — memory, then raw copies of `$MFT`, `$Extend\$UsnJrnl:$J` and the `winevt\Logs` tree, then the volume — because each later step overwrites free pages and advances the journal; **IF** you hold a verified image **THEN** work only inside a read-only mount and record the mount options in the notes.
3. **IF** acquisition mode is cloud or exported **THEN** prefer the provider's immutable copy (snapshot, object version, log-export bucket) over an agent pull from the live instance, because an agent on a compromised host can be made to return a doctored file and the export gives you provider-signed provenance.
4. **IF** two timestamps disagree **THEN** branch on the size of the delta before alleging timestomp: whole-hour or 30/45-minute offsets are a zone or DST interpretation error, sub-second truncation combined with an SI/FN creation-order inversion is tooling, and a delta under roughly two seconds is ordinary create-then-write behaviour.
5. **IF** a channel is short or starts abruptly **THEN** read three things together — oldest `EventRecordID`, continuity of `EventRecordID`, and the presence of 1102/104/1100 — because a cleared channel, a rotated channel and a re-created channel are indistinguishable until all three are compared.
6. **IF** `$J` is present but spans only hours on a long-lived host **THEN** check the journal ID and maximum size, and look for `deletejournal` in process-creation or prefetch evidence; **IF** `$J` is absent altogether **THEN** report `INCONCLUSIVE (Journal Absent)` and pivot to `$LogFile` and MFT ordering instead of asserting deletion.
7. **IF** telemetry covering `timestamp anomaly` / `log gap` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the offensive mechanics or the preconditions an adversary must satisfy **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Timestamp rewrite suspected on one file | [`QUERIES.md`](QUERIES.md) (`$SI` versus `$FN` class) | Attribute-level comparison, not a directory listing |
| Whole channel or journal missing | [`QUERIES.md`](QUERIES.md) (bookend and continuity class) | Oldest-record and `EventRecordID` reasoning |
| Need exact flags and read-only invocation | [`TOOLS.md`](TOOLS.md) | MFTECmd, EvtxECmd, TSK, Volatility 3 |
| Need to know whether the hole is expected | [`SCENARIOS.md`](SCENARIOS.md) | Retention and rollover patterns that mimic wiping |
| Need containment and preservation order | [`PLAYBOOK.md`](PLAYBOOK.md) | Volatile-first handoff before any remediation |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Same question about a live sensor feed | [`detection-engineering`](../../detection-and-monitoring/detection-engineering/SKILL.md) | Telemetry-gap analysis rather than image analysis |
| Need the Linux journal equivalent | [`linux-forensics`](../linux-forensics/SKILL.md) | auditd and journald continuity live with that slug |

## Procedure

1. **Prove the evidence source and its integrity before interpreting any hole.** Record the acquisition method, the SHA-256 of the image or container, and the exact read-only state used for analysis (write blocker, `-o ro,loop`, `immutable=1` for SQLite, provider snapshot ID). An absence read from a source whose provenance is unrecorded cannot be distinguished from an absence the analyst created by writing to it.
2. **Choose the branch from what the platform actually records.** NTFS gives you the SI/FN pair and `$J`; ext4 gives you inode timestamps plus the journal and auditd; APFS gives you the unified log and FSEvents. Pick the branch that the filesystem and the audit configuration can support, and state the branch in the output so a reader can see which class of tampering was even observable.
3. **Build a baseline-versus-probe differential on the same host.** Probe means the window and paths of interest; baseline means an equivalent earlier window, or a peer host of the same build, or the same file's own history in `$J`. The finding is the difference in behavior — a channel that stops while the journal keeps writing, a directory whose prefetch entries stop while execution evidence elsewhere continues — not any single count.
4. **Name the stop condition and honor it.** Declare `Inconclusive` when the required artifact was never collected, when the journal's own ID shows it was recreated at a time you cannot bound, when clock skew between sources exceeds the precision you need, or when the only remaining evidence is unallocated space. Do not convert these into a softened "probably clean".
5. **State what counts as proof.** Proof is two independently written artifacts agreeing inside a stated tolerance: an SI/FN inversion plus a `BasicInfoChange` USN record within the same second; a channel whose oldest record equals its own 1102 timestamp plus an unexplained 1100 or service stop; a prefetch void plus `EnablePrefetcher` rewritten in the registry. One artifact alone is a lead — label it as one.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `$SI` born earlier than `$FN` born, or `$SI` sub-second field zeroed | NTFS MFT attribute divergence (0x10 versus 0x30) | A user-mode timestamp rewrite occurred for that file on NTFS; proves the metadata moved, not the actor |
| `$J` record with `BasicInfoChange` followed by a `Close` carrying an older timestamp | USN change journal record stream | The file's metadata moved backwards relative to journal sequence on NTFS, an ordering the kernel never produces |
| Newly created journal ID with USN values restarting near zero, `$J` minutes old on a host up for weeks | USN journal metadata | The journal was deleted and recreated; proves tampering only when journal size and uptime rule out rollover |
| Oldest surviving `EventRecordID` equals the timestamp of the channel's own 1102 or 104 | Windows EVTX channel | That channel was cleared after the incident window; proves refresh, says nothing about what was removed |
| `EventRecordID` jump with no 1102 or 104 anywhere in the channel | Windows EVTX channel | Records were removed by a tool that edits the file rather than by the native clear path |
| Prefetch directory nearly empty while uptime and `$J` show months of activity | Windows execution artifact set plus registry | Execution history was suppressed or purged; weak alone, strong when `EnablePrefetcher` was also changed |
| Rename chain of mask-like names (`AAAA.AAA`, `BBBB.BBB`) ending in delete | USN journal record stream | A secure-delete utility ran against that path; proves tool use, not the content destroyed |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`timestamp anomaly`):**

```text
# Reads only the rendered view the OS shows, and only the newest records.
Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object TimeCreated, Id
# A short log is then called "cleared", although the channel may simply have
# rolled at its configured size or been re-created by a servicing update.
```

**Behavior-Anchored Detection & Guarded Triage (`timestamp anomaly` — CWE-345):**

```powershell
# Bookend the channel, then ask whether a clear record sits at the boundary.
$oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
$clear  = Get-WinEvent -LogName Security -MaxEvents 1 -FilterXPath '*[System[EventID=1102]]'
$cfg    = (Get-WinEvent -ListLog Security) | Select-Object MaximumSizeInBytes, LogMode, RecordCount
[pscustomobject]@{
  OldestRecord = $oldest.TimeCreated
  OldestName   = $oldest.ProviderName
  ClearSeen    = [bool]$clear
  ClearTime    = $clear.TimeCreated
  Size         = $cfg.MaximumSizeInBytes
  Mode         = $cfg.LogMode
}
# Finding requires the clear record to BE the oldest survivor, or a record-ID
# discontinuity that the configured size and retention cannot explain.
# Channel absent or service stopped -> Disposition: INCONCLUSIVE (Telemetry Gap)
```

**Why this matters:** the strong form reads the channel's own boundaries and configuration before interpreting a short log, so rollover and re-creation are excluded by evidence rather than asserted away, and a missing channel is routed to `Inconclusive` instead of `Clean`.

## When It Is NOT This Issue

- **Backup, restore or copy with timestamp preservation:** `robocopy /COPY:T`, archive extraction and restores write the original `$SI` times onto a newly created file, so `$SI` predates `$FN` by the age of the source with no adversary involved. Ask whether the path was restored before calling timestomp.
- **Timezone and DST rendering:** a parser that reads `$SI` as UTC while the reporting tool renders local time produces a clean whole-hour inversion on every file in the set. If the delta is exactly one or two hours across thousands of records, suspect the report, not the host.
- **Servicing and cleanup utilities:** feature updates, disk cleanup and defragmentation rewrite metadata in bulk and truncate prefetch by design. A void that coincides with a build change or a scheduled maintenance window is expected, not hostile.
- **Antivirus quarantine and release:** quarantine moves a file into a container and restores it with new timestamps and its own USN storm. Check the endpoint product's own audit trail for the file before treating the change as manual.
- **Log size limits and GPO changes:** `MaximumSizeInBytes`, `LogMode` and an auto-archive path explain a channel that begins days ago, and a policy refresh explains several channels changing at once. Read configuration before drawing a conclusion from duration.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `timestamp anomaly` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the image or container used carries a recorded SHA-256 and was analysed read-only, and the acquisition mode is stated in the output.
- [ ] **Branch justified:** the chosen artifact class is one the platform actually records, and the output names which classes of tampering were observable and which were not.
- [ ] **Differential defined:** a baseline (earlier window, peer host, or the file's own `$J` history) was compared against the probe window, and the reported finding is the delta.
- [ ] **Stop condition cleared or declared:** journal re-creation, clock skew, retention and uncollected channels were each explicitly resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: anti-forensics-detection
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `anti-forensics-detection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
