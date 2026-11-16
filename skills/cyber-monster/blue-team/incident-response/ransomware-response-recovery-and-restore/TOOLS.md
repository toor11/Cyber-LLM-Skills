# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ransomware-response-recovery-and-restore`](SKILL.md) | Family: **Incident Response**

Verified restore-readiness tooling. Everything here inspects catalogues, immutability state and restored content; none deletes a restore point, expires a chain or overwrites original media. Confirm option names with `<tool> --help` — backup CLI syntax varies substantially between products and versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-VBRBackup` / `Get-VBRBackupRepository` | `Get-VBRBackup`, `Get-VBRBackupRepository` | Inspect points and the target's configured immutability interval | Windows (Veeam) |
| `Get-VBRRestorePoint` | `Get-VBRRestorePoint -Name <vm>` | Enumerate points per object before selecting a restore source | Windows (Veeam) |
| `wbadmin` | `wbadmin get versions`, `wbadmin get items -version:<id>` | Read-only catalogue and content listing on Windows Server Backup | Windows Server |
| `aws s3api` | `aws s3api get-object-lock-configuration --bucket <b>` · `aws s3api list-object-versions --bucket <b> --prefix <p>` | Prove object-lock and version retention on a cloud backup bucket | Cross-platform |
| `Get-FileHash` | `Get-FileHash -Algorithm SHA256 <path>` | Post-restore fidelity sampling against the restore source | Windows |
| `rsync` | `rsync -ain --stats <src>/ <dst>/` | Dry-run (`-n`) comparison of restored data against source before any sync | Linux / macOS |

## Minimal Script Shape

The shape below decides whether a restore may proceed at all, and refuses on the three conditions that cause re-infection: a point newer than the implant, an unverified immutability claim, and an untested closure. It is read-only and exits non-zero rather than proceeding.

```powershell
# restore-gate.ps1 — read-only gate. Refuses rather than guesses.
[CmdletBinding()] param(
    [Parameter(Mandatory)][datetime]$FirstPreImpactArtifactUtc,
    [Parameter(Mandatory)][string]$EntryVector,
    [string]$RepoName = "bkprepo-primary"
)
$ErrorActionPreference = 'Stop'
$fail = @()

# Gate 1: provenance. The point must predate the earliest pre-impact artifact.
$points = Get-VBRBackup | ForEach-Object {
    $j = $_
    $j.GetAllStorages() | ForEach-Object {
        [pscustomobject]@{ Job=$j.JobName; PointUtc=$_.CreationTime.ToUniversalTime() }
    }
} | Sort-Object PointUtc -Descending

$usable = $points | Where-Object { $_.PointUtc -lt $FirstPreImpactArtifactUtc }
if (-not $usable) { $fail += "No restore point predates the earliest pre-impact artifact ($FirstPreImpactArtifactUtc)." }

# Gate 2: immutability and separation, read from configuration not from policy text.
$repo = Get-VBRBackupRepository -Name $RepoName -ErrorAction SilentlyContinue
if (-not $repo) {
    $fail += "Repository '$RepoName' not found - separation cannot be attested."
} elseif (-not $repo.ImmutabilityInterval -or $repo.ImmutabilityInterval -eq 0) {
    $fail += "Repository '$RepoName' reports no immutable interval - treat as mutable and suspect."
}

# Gate 3: closure. A vector that has not been re-tested is an open vector.
$closure = Read-Host "Enter the observed failure reason when re-authenticating via '$EntryVector' (blank = not tested)"
if ([string]::IsNullOrWhiteSpace($closure)) {
    $fail += "Entry vector '$EntryVector' closure was not demonstrated."
}

if ($fail) {
    $fail | ForEach-Object { Write-Warning $_ }
    Write-Output "RESTORE BLOCKED - data-only recovery or further containment work required."
    exit 2
}

Write-Output "Gates passed. Candidate restore points:"
$usable | Select-Object -First 5 | Format-Table -AutoSize
```

## Notes That Prevent Wrong Runs

- `Get-VBRBackup` and `wbadmin get versions` are read-only. The destructive counterparts — forgetting a chain, expiring a repository, deleting a version — must never appear in a recovery script.
- An incremental restore replays its parent chain. A leaf timestamp older than the implant does not make the chain safe; walk the chain and take the oldest safe full.
- `aws s3api get-object-lock-configuration` proves the bucket's retention rule; it does not prove that the objects within it were written under that rule. Check object-level retention on a sample before relying on it.
- Restore validation must run against a restored copy, never against the backup source in place. A validation script that writes to the source destroys the artifact it is supposed to protect.
- `rsync -ain` is a dry run. Dropping the `n` turns verification into a synchronization that can overwrite evidence.
