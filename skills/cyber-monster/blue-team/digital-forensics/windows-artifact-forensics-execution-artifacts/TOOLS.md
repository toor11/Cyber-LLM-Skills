# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-artifact-forensics-execution-artifacts`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for the five Windows execution artefacts. Confirm options with `<tool> --help`; the Zimmerman tool set uses `--csv` plus an optional `--csvf` filename, and the flag names differ subtly between tools.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `PECmd` | `PECmd.exe -d <PrefetchDir> --csv <out> --csvf prefetch.csv` | Prefetch parsing: run count, last-run timestamps, volume serial, device path | Windows |
| `AmcacheParser` | `AmcacheParser.exe -f <Amcache.hve> --csv <out>` | Identity: path, SHA-1 prefix hash, publisher, first-observed time | Windows |
| `AppCompatCacheParser` | `AppCompatCacheParser.exe --SYSTEM <SYSTEM> --csv <out>` | ShimCache entries including the modern execution flag | Windows |
| `SrumECmd` | `SrumECmd.exe -d <sru> -r <SOFTWARE> --csv <out>` | Per-SID application and network resource use from `SRUDB.dat` | Windows |
| `RECmd` and `rla` | `RECmd.exe -f <SYSTEM> --kn "ControlSet001\Services\bam\State\UserSettings" --csv <out>`, with `rla.exe -f <hive> -l <dir>` first when a tool cannot replay | BAM/DAM last-execution values, after replaying `.LOG1`/`.LOG2` so late writes are not lost | Windows |
| `MFTECmd` | `MFTECmd.exe -f <$MFT> --csv <out>` | The filesystem side: creation and modification times for the same image path | Windows |

## Minimal Script Shape

The shape below parses Prefetch and SRUM, joins them on path and timestamp, and labels each result with the claim class so an execution statement is never built from a single artefact. Read-only against the collected files.

```powershell
# exec-join.ps1 — Prefetch timing joined to SRUM per-SID attribution.
param(
  [string]$PrefetchDir = "C:\case\C\Windows\Prefetch",
  [string]$SruDir      = "C:\case\C\Windows\System32\sru",
  [string]$Software    = "C:\case\C\Windows\System32\config\SOFTWARE",
  [string]$OutDir      = "C:\case\derived",
  [int]$ToleranceSec   = 60
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

PECmd.exe -d $PrefetchDir --csv $OutDir --csvf prefetch.csv | Out-Null
SrumECmd.exe -d $SruDir -r $Software --csv $OutDir | Out-Null

$pf = Import-Csv "$OutDir\prefetch.csv" | Where-Object { $_.SourceFilename }
$sru = Get-ChildItem $OutDir -Filter "SRUM_*.csv" | ForEach-Object { Import-Csv $_.FullName }

foreach ($row in $pf) {
    $t = [datetime]$row.LastRunTimestamp
    $match = $sru | Where-Object {
        $_.App -eq $row.ExecutablePath -and
        $_.Timestamp -and [math]::Abs(([datetime]$_.Timestamp - $t).TotalSeconds) -le $ToleranceSec
    } | Select-Object -First 1

    [pscustomobject]@{
        Image          = $row.SourceFilename
        LastRun        = $t
        RunCount       = $row.RunCount
        VolumeSerial   = $row.VolumeSerialNumber
        PrefetchClaim  = "executed"
        SrumClaim      = if ($match) { "attributed SID $($match.UserSid)" } else { "no SRUM row within ${ToleranceSec}s" }
        Corroborated   = [bool]$match
    }
} | Export-Csv "$OutDir\exec_joined.csv" -NoTypeInformation
```

## Notes That Prevent Wrong Runs

- `SrumECmd` writes one CSV per SRUM table; the per-SID application table and the network table are separate files. Join them on application ID and timestamp rather than assuming a single output.
- A dirty `SRUDB.dat` is normal after a live acquisition. Collect the `SRU` transaction logs with it; `SrumECmd` handles the repair, but a database parsed without its logs yields a partial picture.
- `AppCompatCacheParser` output includes an execution-status column only on builds that support it. Verify the tool version predates nothing in your case — older builds show an empty column that reads like "not executed".
- `PECmd` and `AmcacheParser` both accept a directory as well as a single file; using `-d` on a triage collection is faster and reduces the chance of picking the wrong hive.
