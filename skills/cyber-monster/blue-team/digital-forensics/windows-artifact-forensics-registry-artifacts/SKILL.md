---
name: windows-artifact-forensics-registry-artifacts
description: Windows registry artefacts. Covers NTUSER and system hive keys revealing execution, persistence, USB history and configuration changes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["registry forensics", "ntuser.dat analysis", "registry persistence"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [windows-artifact-forensics, windows-artifact-forensics-execution-artifacts, windows-artifact-forensics-event-log-artifacts, windows-artifact-forensics-file-system-artifacts]
parent: windows-artifact-forensics
---

# Windows Artifact Forensics Registry Artifacts - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

A registry hive is a file of 4 KB bins, each holding a cell; keys are cells containing subkey and value lists, and values are cells containing typed data. Every key cell carries a `LastWrite` timestamp that the kernel updates when the key's contents change — not when a value inside it is read, and not necessarily when a subkey is written, since subkey creation updates the subkey and the parent's index rather than the parent's own data. That nuance is why `LastWrite` is a change timestamp for the key's own values and a weaker signal for structural changes beneath it. Since Windows 8.1 every hive has an associated `.LOG1` and `.LOG2`, and a modification counts as durable once it reaches the log; the primary hive file can lag the logs by a noticeable interval, so a hive copied from a running system is frequently *dirty* — its base block's primary and secondary sequence numbers disagree — and its most recent changes exist only in the logs. The consequence for investigation is direct: parsing a dirty hive without replaying its logs silently presents a state older than the incident, and a persistence value written minutes before collection will be missing while the hive looks perfectly well-formed. Artefacts differ in what they prove. `RunMRU`, `TypedPaths` and `RecentDocs` record user-interface history. `UserAssist` records GUI-launched programs with a run count and last-execution time in ROT13-encoded value names. `USBSTOR` and `MountedDevices` record device and volume history. `Services` and `Run` keys record configuration that may or may not have ever executed.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `windows-artifact-forensics-registry-artifacts` **THEN** start at parent class [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) first.
2. **IF** the hive was captured while the system was running **THEN** assume it is dirty and replay `.LOG1`/`.LOG2` into a clean copy before parsing; **IF** you only hold the primary hive with no logs **THEN** declare that the last changes may be missing rather than presenting the parse as current.
3. **IF** the artefact is a per-user hive **THEN** map the SID to a profile path through `ProfileList` before attributing any activity to a person; `NTUSER.DAT` alone does not name its owner.
4. **IF** the question is "did this program execute" **THEN** use `UserAssist` or `BAM` and treat `Run`/`RunMRU` as configuration and typed-input history respectively; **IF** you only hold a persistence key **THEN** report configured persistence, not execution.
5. **IF** the hive is `SYSTEM` and you need the active control set **THEN** read `Select\Current` first, because `ControlSet00N` numbering does not tell you which one is live.
6. **IF** telemetry source covering `RunMRU` or `UserAssist` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `windows-artifact-forensics-registry-artifacts` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need to prove an executed program rather than a configured one | [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) | Prefetch and SRUM carry execution evidence |
| Need the event that accompanied a key change | [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) | 4657 and Sysmon 12/13/14 record registry writes |

## Procedure

1. **Confirm which hive you hold, whether it is dirty, and which control set is live.** Record the hive's SHA-256, the presence of `.LOG1`/`.LOG2`, and the base block's primary and secondary sequence numbers. Then read `Select\Current` for `SYSTEM` and `ProfileList` for `SOFTWARE`, so every later statement names the correct control set and the correct profile owner.
2. **Choose the branch from what the key class can prove.** Configuration branch for `Run`, `RunOnce`, `Services` and `Winlogon` — these prove intent, not execution. Interaction branch for `UserAssist`, `RunMRU`, `TypedPaths`, `RecentDocs` and `ShellBags` — these prove user-interface history. Device branch for `USBSTOR`, `MountedDevices` and `Portable Devices` — these prove attachment history. Then replay logs before reading any of them.
3. **Establish the differential against the hive's own history and the fleet's baseline.** Compare a suspect key's `LastWrite` against the surrounding keys in the same parent, and compare the value set against the same key on a peer host of the same build. A persistence value present identically on every host in the fleet is an image baseline; one confined to this host and written inside the incident window is the finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the hive is dirty and the logs were not collected, when the hive came from a shadow copy whose age you cannot establish, when the key's `LastWrite` predates the current control set's creation (indicating a stale control set), or when the value exists but no execution or event artefact can place it in time.
5. **State what counts as proof.** Proof of configured persistence is the key, the value data and its `LastWrite` together with a matching Sysmon 12/13/14 or Security 4657 record inside the same minute. Proof of execution from a registry artefact alone is not available: it requires `UserAssist` or `BAM` plus an independent execution artefact such as Prefetch or SRUM.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `Run` or `RunOnce` value under `NTUSER.DAT` or `SOFTWARE` naming a path in a user-writable directory, with a `LastWrite` inside the incident window | Configuration key plus key timestamp | Proves the autostart entry was created or changed at that time on Windows; proves configuration, not that the target ever executed |
| `UserAssist` value with a ROT13-encoded name, a non-zero run count and a last-execution FILETIME | Per-user interaction key | Proves the user launched that GUI program through Explorer and when it last ran; console and service launches do not appear here |
| `USBSTOR` instance key with a `Properties\{83da6326-...}` first-install, last-arrival and last-removal FILETIME | Device enumeration key in `SYSTEM` | Proves a mass-storage device with that serial was attached to this Windows host and when it arrived and left; it does not prove files were copied |
| `MountedDevices` value mapping `\DosDevices\X:` to a volume GUID that also appears in a user's `MountPoints2` | Volume mapping plus per-user mount history | Proves the drive letter was assigned and that this specific user mounted the volume, which attributes removable-media use to an account |
| `Services` key whose `ImagePath` points outside `System32` with a non-default `Start` value | Service configuration key | Proves a service was configured to run that binary with that start type; the service may never have started, so pair it with a 7045 event |
| `Amcache` `Root\InventoryApplicationFile` entry retained after the binary was deleted from disk | Compatibility inventory hive | Proves the image existed and was inventoried on this host even though the file is gone, which is how a deleted binary's hash survives |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: query Run keys live, call every hit persistence, never replay logs.
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
# Live query returns the current state with no LastWrite, no transaction-log
# replay, no control-set confirmation and no fleet comparison. A value written
# five minutes ago is indistinguishable from one present since imaging, and a
# value deleted two minutes ago is simply gone with no evidence it existed.
```

**High-Signal Grounded Artifact:**

```powershell
# reg-persistence.ps1 — dirty-hive gate, control-set resolution, delta vs peer hosts.
param(
  [string]$HiveDir = "C:\case\C\Windows\System32\config",
  [string]$Baseline = "C:\case\baseline\run_keys.csv",
  [string]$OutDir  = "C:\case\derived"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 1. Dirty-hive gate: refuse to read a hive whose logs were not collected.
$dirty = @()
foreach ($h in 'SOFTWARE','SYSTEM','SAM','SECURITY') {
    $p = Join-Path $HiveDir $h
    if (-not (Test-Path $p)) { continue }
    $logs = Get-ChildItem $HiveDir -Filter "$h.LOG*" -ErrorAction SilentlyContinue
    if (-not $logs) { $dirty += $h }
}
"hives without transaction logs (last changes may be missing): $($dirty -join ', ')" |
    Tee-Object "$OutDir\dirty_hives.txt"

# 2. Resolve the live control set before touching any Services key.
RECmd.exe -f (Join-Path $HiveDir 'SYSTEM') -kn "Select" --csv $OutDir --csvf select.csv | Out-Null
$current = (Import-Csv "$OutDir\select.csv" | Where-Object { $_.ValueName -eq 'Current' }).ValueData

# 3. Extract Run keys with LastWrite, then compare against the fleet baseline.
RECmd.exe -f (Join-Path $HiveDir 'SOFTWARE') --bn "BatchExamples\Kroll_Batch.reb" --csv $OutDir | Out-Null
$run = Import-Csv "$OutDir\*.csv" | Where-Object { $_.KeyPath -match 'CurrentVersion\\Run' }
$base = if (Test-Path $Baseline) { Import-Csv $Baseline } else { @() }

$run | ForEach-Object {
    $row = $_
    $known = $base | Where-Object { $_.ValueName -eq $row.ValueName -and $_.ValueData -eq $row.ValueData }
    [pscustomobject]@{
        ControlSet = $current; Key = $row.KeyPath; Name = $row.ValueName
        Data = $row.ValueData; LastWrite = $row.LastWriteTimestamp
        InFleetBaseline = [bool]$known
    }
} | Export-Csv "$OutDir\run_delta.csv" -NoTypeInformation
```

**Why this matters:** the weak form reads current state with no timestamp and no control-set resolution, so it can neither date a persistence value nor tell a fleet-standard entry from an intruder's. The strong form refuses to proceed silently on a hive without logs, resolves the live control set so `Services` findings name the right branch, and carries a fleet-baseline flag beside each value so the reviewer sees at a glance which entries are novel to this host.

## When It Is NOT This Issue

- **A persistence value present on every host in the fleet:** imaging, management agents and OEM tooling populate `Run` keys everywhere. A value with no `LastWrite` inside the incident window and an identical peer value is a baseline entry, not intrusion.
- **A hive parsed without its transaction logs:** the reported state is older than the incident by an unknown interval. Reporting a missing persistence value from an unreplayed hive is the standard false negative in this artefact class, and it cannot be detected from the parse output alone.
- **`RunMRU` treated as execution evidence:** `RunMRU` records what was typed into the Run dialog, including text that never resolved to a program. It is interaction history, not proof of execution.
- **`Services` key present with no corresponding 7045:** service keys persist after uninstallation and can be created by installers that never start the service. Without a service-install event or a `Start`/`Stop` record, the key proves configuration only.
- **`LastWrite` on a parent key after a subkey change:** structural changes update the subkey and the parent's index, so the parent's own `LastWrite` may not move. An unchanged parent timestamp does not mean nothing beneath it changed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `RunMRU` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Logs collected or gap declared:** `.LOG1`/`.LOG2` presence is recorded for every hive cited, and any hive parsed without them is flagged as potentially stale.
- [ ] **Control set and profile resolved:** `Select\Current` was read before any `Services` reference, and `ProfileList` was used to attribute per-user hives to a profile path.
- [ ] **Claim class stated:** each key cited is labelled configuration, interaction, device or inventory, so none is presented as execution proof without a second artefact.
- [ ] **Fleet baseline applied:** the value set was compared against a peer host of the same build, and baseline matches are marked as such.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: windows-artifact-forensics-registry-artifacts
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Replay before reading:** a hive without its logs is a photograph of an earlier moment. Replaying is cheap and skipping it is the most common source of a confidently wrong timeline.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; replay logs into a new file and keep the original dirty hive and logs as evidence.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/sigmahq (4), CYBER_CPT/ctf_search (4), CYBER_CPT/L5/ctf_search (3), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
