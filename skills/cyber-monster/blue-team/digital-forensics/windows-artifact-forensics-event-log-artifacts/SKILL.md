---
name: windows-artifact-forensics-event-log-artifacts
description: Windows event log artefacts. Covers security, system, Sysmon and PowerShell event log analysis for logon, process and defence evasion events. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["event log forensics", "sysmon analysis", "windows event ids"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [windows-artifact-forensics, windows-artifact-forensics-registry-artifacts, windows-artifact-forensics-execution-artifacts, windows-artifact-forensics-file-system-artifacts]
parent: windows-artifact-forensics
---

# Windows Artifact Forensics Event Log Artifacts - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

An EVTX file is a set of 64 KB chunks; each chunk holds a record table and a template table, and each record is binary XML whose substitution array points into a template that defines the field names. That design explains the two failure modes analysts hit constantly. A record is only as complete as the template that was registered when it was written, so a provider that changed its event schema leaves older records whose fields an updated parser will map incorrectly rather than reject; and a chunk that is torn or partially overwritten takes its records with it while the rest of the file continues to read cleanly, which is why "the log has records before and after the gap" never proves the gap was benign. Event IDs are provider-scoped, not global: Security 4688 comes from the audit process-creation subcategory, Sysmon 1 comes from the Sysmon service's own provider, and PowerShell 4104 comes from `Microsoft-Windows-PowerShell/Operational` and only exists once script-block logging is enabled — a 4104 with `MessageNumber` and `MessageTotal` above 1 is one fragment of a block reassembled by `ScriptBlockId`, so reading fragments in file order produces nonsense. What these logs cannot tell you: they record what a provider chose to emit at the moment of the event, so an event written after the fact by a different component (or replayed with a crafted time) carries its own timestamp and no corroboration; the audit policy state at event time determines whether a category was even logged, and turning a subcategory off leaves no trace of what was missed; and channel clearing removes records without leaving a gap proportional to what was lost.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `windows-artifact-forensics-event-log-artifacts` **THEN** start at parent class [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) first.
2. **IF** the artefact is a live host **THEN** export the channels with their record IDs before querying, because a live query returns only the current window; **IF** the artefact is an offline `.evtx` set **THEN** record the file hashes and the acquisition time first.
3. **IF** the question concerns process creation **THEN** check whether 4688 with command-line auditing was enabled at the time; **IF** it was not **THEN** take the Sysmon branch or declare an audit-policy gap rather than reporting "no process started".
4. **IF** the artefact involves PowerShell **THEN** confirm script-block logging was enabled before treating an absent 4104 as meaningful, and reassemble multi-part blocks by `ScriptBlockId` before reading them.
5. **IF** the host runs Sysmon **THEN** record the configuration version and schema, since Sysmon 4.90 added event 29 `FileExecutableDetected` and events 27/28 are blocking-only and never appear in the log.
6. **IF** telemetry source covering `4624` or `4688` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `windows-artifact-forensics-event-log-artifacts` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the execution artefacts the log should corroborate | [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) | Prefetch, Amcache, SRUM and BAM as the second source |
| Need the registry state behind a persistence event | [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) | Run keys, services, UserAssist and hive recovery |

## Procedure

1. **Confirm the evidence source and the audit state that produced it.** Hash each `.evtx`, record the acquisition method and whether the export came from a live host or a dead image, then establish which channels exist at all and which subcategories were enabled for the incident window. The audit policy is the denominator: without it, an absent 4688 is a statement about configuration, not about execution.
2. **Choose the branch from the provider that actually emits the answer.** Security-channel branch for authentication and audit-policy events, Sysmon branch for process and file telemetry with its configuration version, PowerShell branch for script content with fragment reassembly, and the System/Application branch for service and boot events. Record which branch produced the cited event, because the same act appears differently in each.
3. **Establish the baseline-versus-probe differential by principal and by parent.** Count events per account, per parent process and per source address across the quiet baseline window and the incident window, then compare distributions. A single 4625 is meaningless; the shift in failed-then-successful ratios for one principal against its own history is the finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when a channel is absent, when a subcategory was disabled for part of the window, when the file shows a torn chunk that spans the incident, when records were cleared (1102 or a discontinuity in record IDs), or when the event's provider template cannot be resolved by the parser you have.
5. **State what counts as proof.** Proof is two providers agreeing on the same act within a stated tolerance: a Security 4688 or Sysmon 1 process creation and a filesystem artefact naming the same image within seconds, or a 4624 logon type 3 and a matching service-side authentication record on the target. Two records from the same provider repeating one another is one source, not two.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Security 4688 with a command line containing an encoded or download-cradle pattern, parented by a document reader | Audit process-creation event | Proves the process was created and audited on Windows with command-line auditing enabled; proves the parent-child relationship as the kernel reported it, not who launched the reader |
| Sysmon 1 whose `Image` resolves under a user-writable directory while `ParentImage` is a signed system binary | Sysmon process-create event | Proves a system-signed parent spawned a non-system image on Windows with Sysmon running; the pairing is what distinguishes it from the same image started by the user |
| PowerShell 4104 fragment whose reassembled `ScriptBlockText` contains a download-and-execute sequence, with `MessageNumber`/`MessageTotal` covering the full block | Script-block logging event | Proves the script text was compiled by the PowerShell engine on Windows with script-block logging on; proves text, not execution outcome |
| Security 4624 type 3 with `SubjectUserName` `-` and a machine account, followed within seconds by 4672 for the same logon ID | Authentication plus privilege events | Proves a network logon was granted and special privileges were assigned to that logon session; the logon ID linkage is the mechanism |
| Record-ID discontinuity in a channel with no 1102 in the same window | Channel integrity metadata | Proves records were removed or the file rotated on Windows; the absence of 1102 does not mean the log was not cleared, because clearing can be followed by 1102 being lost too |
| Sysmon 29 `FileExecutableDetected` for a PE written to a removable or temp path, with a Sysmon 1 for the same path minutes later | Sysmon file-create plus process-create | Proves a new PE file appeared and was subsequently executed on Windows; event 29 logs the write without blocking it |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: search one ID with no policy check, no window, no baseline.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'powershell' } | Format-List
# No audit-policy check, so an empty result cannot be interpreted.
# No parent dimension, so the reader-spawned shell is indistinguishable
# from the admin's own console, and no baseline so neither is a finding.
```

**High-Signal Grounded Artifact:**

```powershell
# event-differential.ps1 — prove the subcategory was audited, then diff by parent.
param([datetime]$ProbeStart, [datetime]$ProbeEnd, [datetime]$BaseStart, [datetime]$BaseEnd)

$policy = auditpol /get /subcategory:"Process Creation" | Out-String
if ($policy -notmatch "Success") {
    "GAP: Process Creation auditing not enabled -> INCONCLUSIVE"; return
}

function Get-CreatePairs([datetime]$s, [datetime]$e) {
    $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$s; EndTime=$e} -ErrorAction Stop
    foreach ($x in $ev) {
        $h = @{}
        ([xml]$x.ToXml()).Event.EventData.Data | ForEach-Object { $h[$_.Name] = $_.'#text' }
        # Creator process is the reliable parent for 4688; ParentProcessName needs 2016+ auditing.
        [pscustomobject]@{ Parent = Split-Path $h['CreatorProcessName'] -Leaf
                           Child  = Split-Path $h['NewProcessName'] -Leaf
                           User   = $h['SubjectUserName'] }
    }
}

$base  = Get-CreatePairs $BaseStart  $BaseEnd  | Group-Object Parent,Child,User -AsHashTable -AsString
$probe = Get-CreatePairs $ProbeStart $ProbeEnd | Group-Object Parent,Child,User -AsHashTable -AsString

foreach ($k in $probe.Keys) {
    $b = if ($base.ContainsKey($k)) { $base[$k].Count } else { 0 }
    if ($probe[$k].Count -ge 3 -or $b -eq 0) {
        [pscustomobject]@{ Key = $k; Baseline = $b; Probe = $probe[$k].Count }
    }
}
```

**Why this matters:** the weak form asks one question of one channel and cannot tell a disabled audit subcategory from a quiet host. The strong form checks the subcategory state first and refuses to continue without it, keys the aggregation on the parent-child-user triple so a normal console session and a document-spawned shell separate naturally, and reports the probe count beside the baseline count so the finding is a delta rather than an isolated hit.

## When It Is NOT This Issue

- **An empty 4688 set on a host with process-creation auditing disabled:** this is a configuration gap, not an absence of execution. Confirm the subcategory state before drawing any conclusion, and pivot to Sysmon or to execution artefacts if it was off.
- **A 4104 fragment that reads as gibberish:** multi-part script blocks are fragmented across records by `MessageNumber` and must be reassembled by `ScriptBlockId` in message order. Reading them in file order produces exactly the nonsense that gets mistaken for obfuscation.
- **4624 type 3 storms from a single machine account:** backup agents, monitoring probes and SMB-based scanners authenticate constantly. The volume matters only against that account's own baseline and against the destination service's record of the same logon.
- **Channel-rotation gaps:** when a channel reaches its size limit, the file rolls and record IDs restart. A discontinuity without a matching 1102 is a rollover until proven otherwise; check the file creation time and the presence of archive copies.
- **Sysmon events absent for a technique that should have produced them:** the running configuration controls which events are collected, and events 27/28 exist only in blocking mode and are never logged. An absent Sysmon event may be a configuration decision, not an evasion.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `4624` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Channel inventory taken:** every channel cited was enumerated with its record count and time range, and absent channels are reported as gaps rather than as silence.
- [ ] **Audit policy state established:** the subcategory state for each event ID cited is recorded for the incident window, so an absence is interpreted against configuration.
- [ ] **Fragments reassembled:** any multi-part 4104 was reassembled by `ScriptBlockId` in `MessageNumber` order before its content was quoted.
- [ ] **Provider diversity confirmed:** the proof pair comes from two different providers, not two IDs from the same provider.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: windows-artifact-forensics-event-log-artifacts
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
- [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Policy before events:** the single largest source of wrong EVTX conclusions is reading an absence as a negative when the subcategory was never enabled. Establish the audit state first and write it beside every "no events found" statement.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; export channels to a case directory and never clear or reconfigure logging on a host under investigation without explicit approval.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (3), CYBER_CPT/ctftime (1), CYBER_CPT/github_security_md (1), CYBER_CPT/vcdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
