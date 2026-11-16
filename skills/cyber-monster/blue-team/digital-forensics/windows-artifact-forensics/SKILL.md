---
name: windows-artifact-forensics
description: "Analyses Windows artefacts: registry hives, event logs, prefetch, shimcache and amcache, USN journal, LNK files and jump lists to reconstruct execution and user activity. Use when examining a Windows host."
family: digital-forensics
tier: flagship
triggers: ["windows forensics", "windows artifacts", "prefetch", "shimcache", "usn journal", "registry forensics"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [windows-artifact-forensics-registry-artifacts, windows-artifact-forensics-execution-artifacts, windows-artifact-forensics-event-log-artifacts, disk-forensics-and-artifacts]
---

# Windows Artifact Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **flagship** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

A Windows host records the same act in several independent structures, and the forensic value of the whole set comes from their disagreements as much as their agreements. The registry stores configuration and interaction history in hives that buffer recent changes in `.LOG1`/`.LOG2` transaction logs, so a hive copied from a running system is frequently dirty and its newest values exist only in the logs. Event logs store what providers chose to emit, at the granularity of 64 KB chunks with per-provider templates. Prefetch records image loads while `SysMain` is enabled; Amcache records inventory identity including a prefix SHA-1; ShimCache records paths the compatibility engine examined, which on Windows 10 and later does not prove execution; SRUM records per-SID resource use over roughly 30 to 60 days; the NTFS `$MFT` holds two independent timestamp sets whose disagreement is the timestomping signal, and `$UsnJrnl:$J` records the fact of a metadata change independently of what the metadata now claims. LNK files and jump lists record what a user opened from Explorer and from which volume serial. What no single artefact can tell you: the command line, the intent, or the actor. Each structure has its own retention boundary, its own enablement prerequisite, and its own eviction policy, so an absence is only meaningful after you know which of those applied at the time.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `registry-artifacts` **THEN** switch to [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) (1 hop).
2. **IF** the target specifically involves `execution-artifacts` **THEN** switch to [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) (1 hop).
3. **IF** the target specifically involves `event-log-artifacts` **THEN** switch to [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) (1 hop).
4. **IF** the target specifically involves `file-system-artifacts` **THEN** switch to [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) (1 hop).
5. **IF** the artefact is a dead-box image **THEN** take the image branch and parse everything from the copy; **IF** the artefact is a live host **THEN** take the triage branch and collect volatile state before any registry or log query that touches a mounted volume read-write.
6. **IF** the collection is a KAPE-style triage export rather than a full image **THEN** confirm which hives, which `$MFT`, and which channels actually arrived before claiming an absence from any of them.
7. **IF** telemetry source covering `Prefetch` or `AmCache` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
9. **IF** required preconditions for `windows-artifact-forensics` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `windows-artifact-forensics-registry-artifacts` | [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) | Hive parsing, transaction-log replay, persistence and device history |
| Target matches `windows-artifact-forensics-execution-artifacts` | [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) | Prefetch, Amcache, ShimCache, SRUM and BAM claim classes |
| Target matches `windows-artifact-forensics-event-log-artifacts` | [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) | EVTX structure, audit-policy denominator, 4104 reassembly |
| Target matches `windows-artifact-forensics-file-system-artifacts` | [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) | `$MFT`, `$J`, `$LogFile`, recycle bin and timestomp differentials |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the collection set and the enablement state of each source before parsing anything.** Inventory hives with their `.LOG1`/`.LOG2`, channels with their record counts, the `Prefetch` directory, `SRUDB.dat` with its `SRU` logs, `Amcache.hve`, `$MFT` with `$J`, and the per-user `NTUSER.DAT`/`UsrClass.dat` pairs with their SIDs. For each, record the prerequisite that decides whether an absence is meaningful: `SysMain` state, audit subcategory state, service start type, journal retention window.
2. **Choose the branch from the case's primary question, and name it.** Execution timing takes the execution-artefacts branch. Persistence takes the registry branch. Authentication and defence evasion take the event-log branch. File appearance, deletion and timestomping take the filesystem branch. User intent and file access take the LNK/jump-list branch. Record which branch you took, because a conclusion drawn from the wrong branch is structurally invalid even when every individual step was correct.
3. **Establish the differential on two axes: time and peer.** On time, compare each artefact's candidate row against the artefact's own retention boundary so you can distinguish "not present" from "no longer retained". On peer, compare the same key, value, channel pattern or image against a host of the same build and role. The finding is what survives both comparisons — new to this host, and inside a window the artefact actually covers.
4. **Name the stop condition.** Stop and declare `Inconclusive` when a hive is dirty and its logs were not collected, when a channel's audit subcategory was disabled for part of the window, when the journal's oldest USN postdates the activity, when `SysMain` state is unknown and Prefetch is the only execution source, or when the triage export omitted the artefact entirely.
5. **State what counts as proof.** Proof is two structures that record different things agreeing on one act inside a stated tolerance: a Prefetch run time and an SRUM per-SID row within one minute, a persistence value's `LastWrite` and a Sysmon 12/13 or 4657 record within one minute, a bare journal `BasicInfoChange` and an `$SI`-versus-`$FN` delta on the same file reference. Two columns from one parse are one source.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `Run` value written inside the incident window, absent from the peer baseline, with a matching registry-write event | Registry configuration plus event corroboration | Proves autostart configuration was changed at that time on this Windows host and that the change was audited |
| Prefetch run time joined to an SRUM row for the same path within one minute, with the executing SID | Execution timing plus per-SID attribution | Proves the image was loaded and names which account's session loaded it — the pairing that makes an execution claim attributable |
| Bare journal `BasicInfoChange` joined to an `$SI` earlier than `$FN` on the same `$MFT` record | NTFS metadata pair | Proves a metadata-only rewrite occurred at that timestamp on NTFS, which is the timestomping signature rather than a normal data write |
| LNK file naming a removable volume serial that also appears in `USBSTOR` and in a user's `MountPoints2` | Shell link plus device and mount history | Proves a user opened that path from that specific device, which attributes removable-media file access to an account |
| ShimCache entry for a path with no Prefetch, no SRUM row and no 4688 | Compatibility cache entry | Proves the path was examined on this Windows host; on Windows 10 and later it does not prove the image ran |
| Amcache inventory entry with a prefix SHA-1 for a path that no longer exists on disk | Compatibility inventory hive | Proves the image existed on this host and gives a hash for reputation lookup even after the file was deleted |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: collect a triage folder, run every parser, and narrate the CSV.
KAPE.exe --tsource C: --tdest E:\out --target !SANS_Triage
PECmd.exe -d E:\out\C\Windows\Prefetch --csv E:\csv
RECmd.exe -d E:\out\C --bn Kroll_Batch.reb --csv E:\csv
# Then: "Prefetch shows X ran; registry shows Y persists; therefore Y ran X."
# No enablement state, no retention boundary, no peer baseline, no attempt to
# notice that the hive was dirty and its logs were not collected.
```

**High-Signal Grounded Artifact:**

```powershell
# win-scope.ps1 — readiness matrix first, then one cross-artefact join.
param([string]$Root = "E:\out\C", [string]$OutDir = "E:\derived")
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$cfg = Join-Path $Root 'Windows\System32\config'
$matrix = @(
  [pscustomobject]@{ Source='SYSTEM hive'; Present = Test-Path "$cfg\SYSTEM"; Logs = (Test-Path "$cfg\SYSTEM.LOG1") }
  [pscustomobject]@{ Source='SOFTWARE hive'; Present = Test-Path "$cfg\SOFTWARE"; Logs = (Test-Path "$cfg\SOFTWARE.LOG1") }
  [pscustomobject]@{ Source='Prefetch dir'; Present = Test-Path (Join-Path $Root 'Windows\Prefetch'); Logs = $null }
  [pscustomobject]@{ Source='SRUDB.dat'; Present = Test-Path (Join-Path $Root 'Windows\System32\sru\SRUDB.dat'); Logs = $null }
  [pscustomobject]@{ Source='Amcache.hve'; Present = Test-Path (Join-Path $Root 'Windows\AppCompat\Programs\Amcache.hve'); Logs = $null }
  [pscustomobject]@{ Source='$MFT'; Present = Test-Path (Join-Path $Root '$MFT'); Logs = Test-Path (Join-Path $Root '$Extend\$UsnJrnl`$J') }
)
$matrix | ForEach-Object {
  $_.State = if (-not $_.Present) { 'ABSENT -> no claim possible' }
             elseif ($_.Logs -eq $false) { 'PRESENT, logs missing -> stale risk' }
             else { 'usable' }
  $_
} | Tee-Object "$OutDir\readiness.txt" | Format-Table -AutoSize

# Cross-artefact join: Prefetch load times against SRUM per-SID rows.
PECmd.exe -d (Join-Path $Root 'Windows\Prefetch') --csv $OutDir --csvf prefetch.csv | Out-Null
SrumECmd.exe -d (Join-Path $Root 'Windows\System32\sru') -r "$cfg\SOFTWARE" --csv $OutDir | Out-Null

$pf  = Import-Csv "$OutDir\prefetch.csv" | Where-Object SourceFilename
$sru = Get-ChildItem $OutDir -Filter 'SRUM_*.csv' | ForEach-Object { Import-Csv $_.FullName }

$pf | ForEach-Object {
  $row = $_
  $t = [datetime]$row.LastRunTimestamp
  $m = $sru | Where-Object {
        $_.App -eq $row.ExecutablePath -and $_.Timestamp -and
        [math]::Abs(([datetime]$_.Timestamp - $t).TotalSeconds) -le 60 } | Select-Object -First 1
  [pscustomobject]@{ Image=$row.SourceFilename; Loaded=$t; RunCount=$row.RunCount
                     VolumeSerial=$row.VolumeSerialNumber
                     AttributedSid=$m.UserSid
                     Corroborated=[bool]$m }
} | Export-Csv "$OutDir\exec_joined.csv" -NoTypeInformation
```

**Why this matters:** the weak form narrates each parser in isolation and then asserts a causal chain across them, which no single artefact supports. The strong form prints a readiness matrix that marks every source as usable, stale-at-risk or absent before a single value is quoted, then performs exactly one join — Prefetch against SRUM — whose output carries the attributable SID alongside the load time, so an execution claim arrives already corroborated or visibly uncorroborated.

## When It Is NOT This Issue

- **A triage export missing an artefact entirely:** a KAPE target that did not collect `SRUDB.dat`, or a hive collected without `.LOG1`/`.LOG2`, produces a negative that reflects the collection rather than the host. Establish the readiness matrix before interpreting any absence.
- **Every host in the fleet showing the same artefact:** imaging, OEM tooling and management agents populate identical autostart, service and prefetch entries. A peer comparison that shows no divergence is a baseline finding, and the correct output is a baseline note rather than a case.
- **Prefetch absent on a server SKU:** prefetching is disabled by default on server editions. Reporting "the binary never ran" from an empty Prefetch directory on such a host inverts the meaning of the evidence.
- **ShimCache or Amcache used as an execution proof:** ShimCache attests presence on modern builds, and Amcache's timestamp is first observation. Neither can carry an execution claim alone, whatever the volume of rows.
- **A registry `LastWrite` predating the current control set:** the key belongs to an abandoned control set and never applied to the running configuration. Read `Select\Current` before treating any `Services` timestamp as evidence about the live system.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Prefetch` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Readiness matrix produced:** every artefact cited is marked usable, stale-at-risk or absent, with the prerequisite that decides its meaning recorded beside it.
- [ ] **Branch named:** the artefact branch chosen for the primary question is stated, and no conclusion rests on a source from a different branch.
- [ ] **Both differentials run:** each candidate survives a comparison against its own retention boundary and against a peer host of the same build and role.
- [ ] **Cross-artefact join shown:** the proof pair joins two structures that record different things, with the tolerance in seconds or minutes stated.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: windows-artifact-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Readiness before findings:** the flagship's job is to stop the analyst from quoting a parser before knowing whether the source could have held the answer. Produce the matrix first and keep it in the report.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; collect from a copy or behind a write blocker and direct all parser output into the case directory.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/L5/ctf_search (8), CYBER_CPT/ctf_search (6), CYBER_CPT/oxdf (3), Forensic_Toolkit_Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 1 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
