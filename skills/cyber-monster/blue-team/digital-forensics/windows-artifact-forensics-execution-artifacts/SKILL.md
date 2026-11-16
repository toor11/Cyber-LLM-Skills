---
name: windows-artifact-forensics-execution-artifacts
description: Windows execution artefacts. Covers prefetch, shimcache, amcache, SRUM and BAM to prove what ran and when. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["prefetch analysis", "shimcache", "amcache", "srum"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [windows-artifact-forensics, windows-artifact-forensics-registry-artifacts, windows-artifact-forensics-event-log-artifacts, windows-artifact-forensics-file-system-artifacts]
parent: windows-artifact-forensics
---

# Windows Artifact Forensics Execution Artifacts - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Each execution artefact answers a different question, and conflating them is the most common error in this class. Prefetch is written by the `SysMain` service when an image is first loaded and updated on later loads, storing up to eight last-run times, the run count, the volume serial and device path of the source medium, and the list of files and directories touched during the first ten seconds — so it proves *the image was loaded*, and it only exists when `SysMain` is running and prefetching is enabled for that volume type. Amcache stores path, size, publisher and a SHA-1 for images the compatibility and inventory components examined, calculated over the first portion of large files, and it tracks *first* observation rather than last execution — so it is strongest as an identity artefact (hash, path, publisher) and weakest as a timing artefact. ShimCache (AppCompatCache) records paths and the file's last-modification time as the compatibility engine encountered them, and on Windows 10 and later an entry does not prove execution at all; on modern builds a trailing execution flag exists but must be corroborated. SRUM is an ESE database holding per-application resource use, per-SID attribution, network bytes per interface, and a roughly 30-to-60-day window — the strongest available link between a process and the identity that ran it. BAM/DAM holds per-SID last-execution times for background and desktop activity on recent builds. What none of them can tell you: none records the command line (that is 4688 or Sysmon 1), none survives a volume that was never mounted with the relevant service enabled, and Amcache's first-observed time is not a first-execution time.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `windows-artifact-forensics-execution-artifacts` **THEN** start at parent class [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) first.
2. **IF** the question is "did this binary run" **THEN** lead with Prefetch and require `SysMain` to have been enabled; **IF** it was disabled or the volume was a server volume where prefetching is off by default **THEN** pivot to SRUM or Amcache and state the substitution.
3. **IF** the question is "what was this file" **THEN** lead with Amcache's SHA-1 and publisher; **IF** the question is "when did it first appear" **THEN** use Amcache's first-observed time only as an upper bound, never as execution time.
4. **IF** the only available artefact is ShimCache on Windows 10 or later **THEN** treat it as evidence of presence, not execution, and say so explicitly in the finding.
5. **IF** the host is live **THEN** collect `SRUDB.dat` together with its `SRU` transaction logs and the SOFTWARE hive, because a dirty ESE database cannot be read without its logs and user SIDs cannot be resolved without the hive.
6. **IF** telemetry source covering `Prefetch` or `ShimCache` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `windows-artifact-forensics-execution-artifacts` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the command line the execution artefact cannot hold | [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) | 4688 and Sysmon 1 carry arguments |
| Need the hive keys that store these artefacts | [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) | Amcache, ShimCache and BAM live in hives and need log replay |

## Procedure

1. **Confirm the collection covers the artefact and its prerequisites.** Prefetch requires the `Prefetch` directory plus evidence that `SysMain` was running; SRUM requires `SRUDB.dat` and its transaction logs plus the SOFTWARE hive for SID resolution; Amcache and ShimCache require hives and their `.LOG1`/`.LOG2`. A collected artefact without its prerequisite produces a confident wrong answer.
2. **Choose the branch dictated by the question, not by the artefact you happened to collect.** Execution timing takes Prefetch plus SRUM. Identity takes Amcache's hash. Presence takes ShimCache. Per-user attribution takes SRUM or BAM keyed on SID. Record the branch, because a "did it run" answer built on ShimCache is invalid on modern builds no matter how well it is presented.
3. **Build the differential across the artefact's own coverage window.** Prefetch holds a bounded number of entries and evicts oldest-first, Amcache holds first-observed records indefinitely, and SRUM rolls off in roughly 30 to 60 days. Compare the candidate's timestamp against the artefact's own oldest and newest entry so you know whether the absence of a neighbouring entry is meaningful or simply outside retention.
4. **Name the stop condition.** Stop and declare `Inconclusive` when Prefetch is absent and `SysMain` state is unknown, when the SRUM database is dirty and its logs were not collected, when Amcache is the only source for an execution claim, or when the candidate timestamp falls outside the artefact's retained range.
5. **State what counts as proof.** Proof of execution is Prefetch's run time and SRUM's per-SID record agreeing inside the same minute, or Prefetch plus a 4688/Sysmon 1 for the same image and logon session. Amcache agreeing with itself is identity confirmation, not execution proof, and must never be presented as the second source.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `NAME.EXE-<hash>.pf` with a run count above one and a last-run time inside the window | Prefetch file under `C:\Windows\Prefetch` | Proves the image was loaded on that Windows host while `SysMain` was enabled; the volume serial and device path name the medium it was loaded from |
| SRUM row with the application path, the executing SID and a byte count per interface | ESE table in `SRUDB.dat` | Proves that identity ran that path and moved that many bytes on that interface within SRUM's retention; the per-SID attribution is unique to this artefact |
| Amcache `UnassociatedFileEntries` row carrying a SHA-1 and publisher for a path under a user directory | Amcache hive entry | Proves the image was inventoried on that host and gives its identity for reputation lookup; the timestamp is first observation, not execution |
| AppCompatCache entry for a path with no Prefetch and no SRUM row for the same path | ShimCache entry | Proves the path was examined by the compatibility engine on Windows 10 or later, which is presence rather than execution |
| BAM/DAM value under `Services\bam\State\UserSettings\{SID}` naming a full path with a FILETIME | Registry value in the SYSTEM hive | Proves that SID's last execution time for that path on Windows 10 1709 and later; it holds one timestamp per path, not a history |
| Prefetch whose volume serial differs from the system volume for an image with a system-looking path | Volume-relative metadata in the prefetch file | Proves the image was loaded from a different medium, which is how execution from removable or mounted media is established on Windows |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: one artefact, one timestamp, and a conclusion about execution.
PECmd.exe -d C:\triage\C\Windows\prefetch --csv C:\out
# Pick the newest row, call it "the malware ran at this time".
# No SysMain state, no SRUM/SID attribution, no check that Prefetch was even
# enabled on this build, and no recognition that Prefetch evicts oldest-first
# so a missing entry proves nothing about the retention window's start.
```

**High-Signal Grounded Artifact:**

```powershell
# exec-correlate.ps1 — Prefetch timing against SRUM per-SID attribution.
param([string]$PrefetchCsv, [string]$SrumCsv, [string]$Candidate = "*.exe")

$pf = Import-Csv $PrefetchCsv |
      Where-Object { $_.SourceFilename -like $Candidate } |
      Select-Object SourceFilename, @{n='LastRun';e={[datetime]$_.LastRunTimestamp}},
                    RunCount, VolumeSerialNumber, ExecutablePath

$sru = Import-Csv $SrumCsv |
       Where-Object { $_.App -like $Candidate } |
       Select-Object App, @{n='SruTime';e={[datetime]$_.Timestamp}}, UserSid,
                     BytesSent, BytesReceived, InterfaceLuid

foreach ($row in $pf) {
    $hit = $sru | Where-Object {
        $_.App -eq $row.ExecutablePath -and
        [math]::Abs(($_.SruTime - $row.LastRun).TotalSeconds) -le 60
    }
    [pscustomobject]@{
        Image        = $row.SourceFilename
        PrefetchRun  = $row.LastRun
        RunCount     = $row.RunCount
        VolumeSerial = $row.VolumeSerialNumber
        SrumAgrees   = [bool]$hit
        SrumSid      = ($hit | Select-Object -First 1).UserSid
        SrumBytesOut = ($hit | Select-Object -First 1).BytesSent
    }
}
```

**Why this matters:** the weak form converts one file's newest timestamp into an execution verdict and cannot distinguish "did not run" from "prefetch was disabled" or "the entry was evicted". The strong form joins Prefetch to SRUM on both the path and a 60-second tolerance, which yields the two things Prefetch cannot supply: the SID that ran it and the network volume that session moved — and it carries the volume serial so execution from a non-system medium is visible rather than assumed.

## When It Is NOT This Issue

- **An absent Prefetch entry on a server build or with `SysMain` disabled:** prefetching is off by default on server SKUs and can be disabled by policy. The absence is a configuration property, and concluding "it never ran" from it is the standard error in this artefact class.
- **Prefetch eviction mistaken for non-execution:** Prefetch retains a bounded number of entries and evicts oldest-first, so a busy host can lose a week-old entry while retaining a year-old one. Check the oldest retained timestamp before treating absence as meaningful.
- **Amcache first-observed time reported as execution time:** Amcache records when the image was inventoried, which may precede or follow execution and does not update on later runs. Presenting it as a run time misplaces the activity in the timeline.
- **ShimCache entry treated as execution on Windows 10 or later:** merely browsing a directory can create an entry on older builds, and on modern builds the entry alone does not establish execution. Use it for presence, and pivot to Prefetch or SRUM for the run.
- **SRUM gap explained by retention rather than by absence:** SRUM rolls off after roughly 30 to 60 days and its aggregation windows are not uniform. A missing SRUM row for a date inside the window is meaningful; one outside it is a retention boundary.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Prefetch` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Prerequisite state recorded:** `SysMain` state for Prefetch, transaction logs plus SOFTWARE hive for SRUM, and `.LOG1`/`.LOG2` for Amcache and ShimCache, each confirmed present or recorded as a gap.
- [ ] **Artefact retention bounded:** the oldest and newest retained entry for each artefact is quoted, so an absence is interpreted against coverage rather than assumed.
- [ ] **Claim class stated per artefact:** every artefact used is labelled execution, identity, presence or attribution, never blurred into a single "ran" statement.
- [ ] **Two-source agreement shown:** the execution claim rests on Prefetch plus SRUM or a process-creation event, with the tolerance in seconds stated.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: windows-artifact-forensics-execution-artifacts
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Artefact scope before artefact content:** each of these five answers exactly one question. Writing down which question you are answering, before parsing, prevents the ShimCache-as-execution and Amcache-as-timing errors.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; parsing tools write CSV output, so direct it into the case directory and never over the collected artefacts.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (3), CYBER_CPT/ctf_wiki (2), CYBER_CPT/awesome_list (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
