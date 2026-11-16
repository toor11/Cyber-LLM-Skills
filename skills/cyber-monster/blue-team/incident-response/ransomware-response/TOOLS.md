# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ransomware-response`](SKILL.md) | Family: **Incident Response**

Verified victim-side entry points. Every command is read-only or dry-run first; none contacts an actor, decrypts with an untrusted binary, or writes to evidence media. Confirm flags with `<tool> --help` on the installed version — storage and backup CLIs change option names between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Velociraptor` | `velociraptor --config client.config.yaml query 'SELECT * FROM info()'` | Read-only endpoint state before wider triage collection | Cross-platform |
| `Velociraptor` (`Windows.KapeFiles.Targets`) | `velociraptor artifacts collect Windows.KapeFiles.Targets --args Target=EventLogs,WebRoot` | Triage collection in 0.73–0.74; renamed `Windows.Triage.Targets` in 0.75+ and moved to `Server.Import.Extras` | Windows |
| `Velociraptor` (`winpmem()`) | `SELECT * FROM winpmem()` inside a client query | Memory acquisition without an external image file | Windows |
| `Hayabusa` | `hayabusa csv-timeline -d ./evtx -o timeline.csv -w` | Offline Sigma-matched EVTX timeline when the SIEM feed is off | Windows / Linux / macOS |
| `Get-ChildItem` + `Group-Object` | `Get-ChildItem D:\Shares -Recurse -File`, then `Group-Object Extension`, then `Sort-Object Count -Descending` | Extension inventory for the baseline-versus-probe differential | Windows |
| `vssadmin` / `wbadmin` | `vssadmin list shadows` · `wbadmin get versions` | Read-only enumeration of what shadow copies and backup catalogues still exist | Windows Server |

## Minimal Script Shape

The shape below produces the two facts a ransomware decision needs and nothing else: the per-host onset, and whether a pre-incident restore point exists. It is read-only, writes only to a case folder, and exits non-zero rather than guessing.

```powershell
# onset-and-recovery.ps1 — read-only. No remediation, no decryption, no actor contact.
[CmdletBinding()] param(
    [Parameter(Mandatory)][string]$ShareRoot,
    [Parameter(Mandatory)][datetime]$ProbeStart,
    [string]$CaseDir = ".\case"
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $CaseDir | Out-Null

# Gate 1: audit coverage. Without object-access auditing the share timeline is unprovable.
$audit = auditpol /get /category:"Object Access"
$audit | Out-File "$CaseDir\audit-policy.txt"
if ($audit -notmatch 'Success') {
    Write-Warning "Object Access auditing not recording Success -> share timeline is INCONCLUSIVE"
}

# Gate 2: extension differential, scoped to the probe window only.
$before = Get-ChildItem $ShareRoot -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -lt $ProbeStart | Group-Object Extension |
    Select-Object Name, Count
$before | Export-Csv -NoTypeInformation "$CaseDir\ext-before.csv"

$after = Get-ChildItem $ShareRoot -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -ge $ProbeStart | Group-Object Extension |
    Select-Object Name, Count, @{n='FirstSeen';e={
        ($_.Group | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime.ToUniversalTime()}}
$after | Export-Csv -NoTypeInformation "$CaseDir\ext-after.csv"

# Gate 3: recovery capability. Report, do not attempt restore.
vssadmin list shadows | Out-File "$CaseDir\shadow-copies.txt"
wbadmin get versions    | Out-File "$CaseDir\backup-versions.txt"

$candidates = $after | Where-Object { $_.Name -notin $before.Name }
if ($candidates.Count -eq 0) {
    Write-Output "No new extension in window. Confirm a backup or migration job occupied the window before excluding encryption."
} else {
    $candidates | Format-Table -AutoSize
}
```

## Notes That Prevent Wrong Runs

- Never run a decryptor, a "recovery tool" or an actor-supplied binary against original evidence. Work only on copies, and only after the originals are hashed and stored.
- `vssadmin list shadows` and `wbadmin get versions` are read-only; `delete` on either is the destructive variant and must never appear in a response script.
- Memory acquisition changes the host's state enough that it must be sequenced deliberately: capture before isolation when spread is not active, and accept and record partial capture when it is.
- `Windows.KapeFiles.Targets` moved in Velociraptor 0.75+; a runbook that hardcodes the old artifact name silently collects nothing on a newer server.
- Restoring a backup taken after the implant was resident restores the implant. Always compare the backup point timestamp against the earliest pre-impact artifact before calling the backup clean.
