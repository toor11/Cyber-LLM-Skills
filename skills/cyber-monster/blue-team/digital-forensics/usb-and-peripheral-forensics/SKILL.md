---
name: usb-and-peripheral-forensics
description: "Analyses USB and peripheral artefacts: device connection history, removable storage usage and data transfer evidence. Use when removable media or peripherals are relevant."
family: digital-forensics
tier: leaf
triggers: ["usb forensics", "removable media forensics", "device history"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Usb and Peripheral Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Windows records removable-device history across several stores that answer different questions. `SYSTEM\CurrentControlSet\Enum\USB` holds every USB device the Plug and Play manager enumerated — storage, phones (MTP), cameras, keyboards, hubs — keyed by vendor and product ID, with the instance key naming the device's `iSerialNumber`. `Enum\USBSTOR` narrows to mass-storage devices handled by `usbstor.sys`, and under each instance's `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` the subkeys `0064`, `0065`, `0066` and `0067` hold first-install, first-install-date, last-arrival and last-removal FILETIMEs in UTC. `Enum\SCSI` holds devices that negotiated USB Attached SCSI instead, so a modern external SSD may appear there rather than in `USBSTOR`. `MountedDevices` maps drive letters and volume GUIDs to device signatures, and per-user `NTUSER.DAT\...\Explorer\MountPoints2` attributes a volume to the profile that mounted it. `C:\Windows\INF\setupapi.dev.log` records the first driver installation in *local* time, which is the one timestamp in this set that must be converted through the SYSTEM hive's time zone before comparison. What these cannot tell you: `USBSTOR` proves attachment, never that a file was copied; an instance ID whose second character is `&` is a Windows-generated identifier rather than the device's own serial, so it will not match the same hardware elsewhere; `MountedDevices` entries can be removed with `mountvol /r`, so absence is not proof of non-use; and OS upgrades have been observed to prune parts of the enumeration history.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the host is Windows **THEN** read `SYSTEM\Enum\USB` first to map device classes, then `USBSTOR` and `SCSI` for storage, then `MountedDevices` and `MountPoints2` for volume and user attribution; **IF** the host is Linux or macOS **THEN** pivot to udev or unified-log sources and state the platform change, because none of these keys exist there.
2. **IF** a device instance ID has `&` as its second character **THEN** treat it as a Windows-generated ID and do not match it across hosts; **IF** it is a true serial **THEN** it can be used for cross-host device correlation.
3. **IF** the question is whether files moved **THEN** require a second artefact — LNK, jump list, USN journal, Sysmon 29 or shellbag — because `USBSTOR` proves attachment only.
4. **IF** you are comparing `setupapi.dev.log` with a registry FILETIME **THEN** convert the log's local timestamps through the SYSTEM hive's time zone and DST rule first, and report both values rather than silently preferring one.
5. **IF** the only evidence is a `MountedDevices` entry **THEN** treat it as weak, because those entries can be cleared; **IF** the entry is absent **THEN** do not report the device was never mounted.
6. **IF** telemetry source covering `USBSTOR` or `setupapi` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `usb-and-peripheral-forensics` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the registry key semantics in depth | [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) | Hive replay and per-user attribution |
| Need to prove a file was opened from the device | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | LNK and jump-list volume serial correlation |

## Procedure

1. **Confirm the platform, the hive set and the log presence before reading device history.** Record which hives arrived with `.LOG1`/`.LOG2`, whether `setupapi.dev.log` is present with its archive copies, and whether `Partition/Diagnostic` and `Kernel-PnP` event channels were collected. `USBSTOR` values written minutes before collection may exist only in the transaction logs of a dirty SYSTEM hive, so the replay gate from the registry branch applies here unchanged.
2. **Choose the branch from the question.** Attachment history takes the enumeration branch (`Enum\USB`, `USBSTOR`, `SCSI`). Volume and drive-letter attribution takes the mount branch (`MountedDevices`, `MountPoints2`, `Partmgr\DiskId`). First-contact timing takes the install branch (`setupapi.dev.log` plus `Properties` timestamps). Data-transfer proof takes the file-access branch (LNK, jump list, USN journal, Sysmon 29) and belongs to the Windows-artefact skills.
3. **Establish the differential across the device's own lifecycle and against the fleet.** Order first-install, last-arrival and last-removal for the device, then compare against the same device ID on a peer host and against the host's own device population. A device present on every host in the fleet is provisioned hardware; a device with a single arrival inside the incident window and no removal is the finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the SYSTEM hive is dirty and unreplayed, when the instance ID is Windows-generated so cross-host identity is unavailable, when `setupapi.dev.log` has rotated past the window and no archive exists, or when the only artefact is a `MountedDevices` entry that may have been cleared.
5. **State what counts as proof.** Proof of attachment is a `USBSTOR` instance with `Properties` FILETIMEs plus a matching `setupapi.dev.log` install section for the same instance ID, with both converted to UTC and the conversion shown. Proof of file access additionally requires a LNK or jump-list entry naming that volume serial, or a journal record for a path on that volume — attachment alone is never proof of transfer.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `USBSTOR` instance key with `Properties\{83da6326-...}\0066` last-arrival and `0067` last-removal FILETIMEs | Device enumeration key with typed properties | Proves a mass-storage device with that instance ID arrived and was removed at those UTC times on Windows; proves nothing about what was read or written |
| `setupapi.dev.log` section naming the same instance ID, with a local-time timestamp offset from the registry by an exact hour | Plain-text PnP install log | Proves first driver installation for that device; an exact-hour divergence is a DST or time-zone conversion error, not a second event |
| `Enum\USB` VID/PID matched to a `USBSTOR` serial, with the serial reused under `SCSI` on a UASP device | Cross-key device identity | Proves the same physical device negotiated both protocols on that host, which is normal for modern external SSDs and not evidence of two devices |
| `MountPoints2` volume GUID under one user's `NTUSER.DAT` matching a `MountedDevices` letter mapping | Per-user mount history plus volume mapping | Proves that specific user mounted that volume on that Windows host, which is the attribution step `USBSTOR` cannot supply |
| LNK file whose `VolumeSerialNumber` equals the device's `Partmgr\DiskId`-derived volume, pointing at a file on that volume | Shell link plus volume identity | Proves a user opened that file from that volume, which converts attachment history into file-access evidence |
| Sysmon 29 `FileExecutableDetected` for a PE written to a path on the removable volume | Sysmon file-create event | Proves a new executable appeared at that path without Sysmon blocking it; pair with a Sysmon 1 for the same path to prove it then ran |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: list USBSTOR keys, declare the device was used to exfiltrate.
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s
# Output: every USB stick ever plugged into the build image, with no
# Properties timestamps read, no MountPoints2 attribution, no setupapi
# comparison, and no file-access artefact at all. Conclusion: "data was
# stolen via USB" — supported by nothing in the output.
```

**High-Signal Grounded Artifact:**

```powershell
# usb-lifecycle.ps1 — replay gate, UTC-normalised timeline, per-user attribution.
param(
  [string]$HiveDir = "C:\case\C\Windows\System32\config",
  [string]$Profiles = "C:\case\C\Users",
  [string]$SetupApi = "C:\case\C\Windows\INF\setupapi.dev.log",
  [string]$OutDir   = "C:\case\derived"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 0. Dirty-hive gate: USBSTOR properties written late may exist only in the logs.
$sys = Join-Path $HiveDir 'SYSTEM'
if (-not (Test-Path "$sys.LOG1") -and -not (Test-Path "$sys.LOG2")) {
    "STALE RISK: SYSTEM hive has no transaction logs" | Tee-Object "$OutDir\gaps.txt"
}

RECmd.exe -f $sys -kn "ControlSet001\Enum\USBSTOR" --csv $OutDir --csvf usbstor.csv -q | Out-Null
$usb = Import-Csv "$OutDir\usbstor.csv"

# 1. Lifecycle per instance, with the GUID-scoped property timestamps decoded.
$timeline = foreach ($dev in ($usb | Where-Object { $_.KeyPath -match 'USBSTOR\\Disk' } |
                              Group-Object { ($_.KeyPath -split '\\')[2] })) {
    $inst = $dev.Name
    $props = $dev.Group | Where-Object { $_.KeyPath -match '83da6326' }
    [pscustomobject]@{
        Instance      = $inst
        GeneratedId   = ($inst.Length -gt 1 -and $inst[1] -eq '&')
        FirstInstall  = ($props | Where-Object ValueName -eq '0064').ValueData
        LastArrival   = ($props | Where-Object ValueName -eq '0066').ValueData
        LastRemoval   = ($props | Where-Object ValueName -eq '0067').ValueData
    }
}
$timeline | Export-Csv "$OutDir\usb_timeline.csv" -NoTypeInformation

# 2. Per-user attribution through MountPoints2, joined on volume GUID.
Get-ChildItem $Profiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $nt = Join-Path $_.FullName 'NTUSER.DAT'
    if (-not (Test-Path $nt)) { return }
    RECmd.exe -f $nt -kn "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" `
      --csv $OutDir --csvf "mp_$($_.Name).csv" -q | Out-Null
    Import-Csv "$OutDir\mp_$($_.Name).csv" | Where-Object { $_.KeyPath -match 'Volume\{' } |
      ForEach-Object { [pscustomobject]@{ User=$_.Name; VolumeKey=$_.KeyPath } }
} | Export-Csv "$OutDir\mountpoints2.csv" -NoTypeInformation

# 3. Report setupapi separately: it is local time and must not be silently merged.
if (Test-Path $SetupApi) {
    Select-String -Path $SetupApi -Pattern 'USBSTOR\\Disk' -Context 0,2 |
      Select-Object -First 40 | Out-File "$OutDir\setupapi_local_time.txt"
}
```

**Why this matters:** the weak form lists enumeration keys and then accuses, with no timeline and no attribution. The strong form gates on the hive's transaction logs, decodes the GUID-scoped property values into a per-instance arrival and removal timeline, flags Windows-generated instance IDs so they are not misused for cross-host matching, and keeps `setupapi.dev.log` in a separate local-time file rather than silently merging it with UTC FILETIMEs — the exact mistake that turns a DST offset into a phantom second device.

## When It Is NOT This Issue

- **Devices present in the base image:** keyboards, mice, hubs, Bluetooth radios and provisioned encrypted drives populate `Enum\USB` on every host of a build. Compare against a peer host before treating an enumeration entry as user action.
- **External SSDs that appear only under `Enum\SCSI`:** USB Attached SCSI devices are enumerated by a different driver and may have no `USBSTOR` instance at all. An empty `USBSTOR` set on a host that plainly uses an external SSD is a protocol artifact, not concealment.
- **`MountedDevices` entries that were cleared:** `mountvol /r` and some cleanup tools remove stale mappings, and OS upgrades have been observed to prune enumeration history. Absence proves nothing about whether a device was ever attached.
- **A one-hour discrepancy between `setupapi.dev.log` and a registry FILETIME:** this is a local-time-versus-UTC conversion, usually DST. Report both values and the conversion applied; never silently pick one and describe it as agreement.
- **An instance ID matching nothing on another host:** if the second character is `&`, the identifier was generated on that machine. Cross-host "same device" claims built on such an ID are false by construction.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `USBSTOR` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Hive replay gate applied:** `SYSTEM` and every per-user `NTUSER.DAT` cited were checked for `.LOG1`/`.LOG2`, and any parsed without them is flagged as stale.
- [ ] **Instance ID class stated:** every device identifier is labelled hardware serial or Windows-generated, and cross-host claims use only hardware serials.
- [ ] **Time bases separated:** registry FILETIMEs are reported in UTC and `setupapi.dev.log` values in local time with the conversion shown, never silently merged.
- [ ] **Transfer claim backed:** any statement about files moving cites a LNK, jump list, journal record or Sysmon event naming the same volume, not the enumeration key alone.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: usb-and-peripheral-forensics
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

- **Attachment is not transfer:** the single most common error in this skill is escalating a device enumeration key into a data-theft claim. Attachment and file access are separate branches with separate artefacts.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; any removable device identified as evidence should be acquired under the case's evidence handling rules before it is reconnected anywhere.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctftime (4), CYBER_CPT/lolbas (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
