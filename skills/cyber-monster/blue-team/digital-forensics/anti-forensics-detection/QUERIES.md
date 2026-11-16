# Artifacts and Queries

> Sub-skill: [`anti-forensics-detection`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction queries and artifact-location checks owned by `anti-forensics-detection`. Each class states the expected hit and the false-positive note that must be cleared before the hit is called tampering. Commands are read-only; run them against a verified copy or a read-only mount, never the original media. Field and flag names are those of the tools named here — confirm against the installed version before trusting output.

## Class 1 — Integrity and read-only gate (run before any other class)

Expected hit: every source has a recorded digest, and the mount or open flags show read-only. A class run against a writable source measures your own analysis, not the suspect's activity.

```powershell
Get-FileHash -Algorithm SHA256 D:\evidence\HOST01\disk.E01 | Format-List
Get-FileHash -Algorithm SHA256 D:\evidence\HOST01\$MFT, D:\evidence\HOST01\$J |
  Select-Object Path, Hash
```

```bash
# Confirm the mount really is read-only before parsing anything from it.
findmnt -no OPTIONS /mnt/case
```

False-positive note: an NTFS mount via `ntfs-3g` defaults to read-write and will replay `$LogFile` on mount, changing the volume. If `findmnt` shows `rw`, stop and re-mount read-only; a digest taken after that mount no longer describes the seized state.

## Class 2 — NTFS timestamp divergence ($SI versus $FN)

Expected hit: for the files in scope, `$SI` and `$FN` creation times within a couple of seconds of each other, with natural sub-second digits in both. An inversion, or `$SI` truncated to `.0000000`, is the candidate.

```powershell
# --at forces both attribute sets into the CSV; without it only differences are shown.
MFTECmd.exe -f "D:\evidence\HOST01\$MFT" --csv D:\out --csvf mft_timestomp.csv --at --dt "yyyy-MM-dd HH:mm:ss.fffffff"
Import-Csv D:\out\mft_timestomp.csv |
  Where-Object { [datetime]$_.Created0x10 -lt [datetime]$_.Created0x30 } |
  Select-Object ParentPath, FileName, Created0x10, Created0x30, LastModified0x10, FileSize
```

False-positive note: a file restored from backup, extracted from an archive, or copied with `robocopy /COPY:T` legitimately has `$SI` older than `$FN`. Confirm the path was not restored and look for a `BasicInfoChange` record before calling it timestomping.

## Class 3 — USN journal continuity and metadata-change records

Expected hit: a journal whose ID matches the volume's, whose first USN is not near zero on a long-lived host, and whose records include `BasicInfoChange` entries for the suspect paths.

```powershell
# Parse $J alone, then again with -m to resolve parent paths as they were at write time.
MFTECmd.exe -f "D:\evidence\HOST01\$J" --csv D:\out --csvf usn.csv
MFTECmd.exe -f "D:\evidence\HOST01\$J" -m "D:\evidence\HOST01\$MFT" --csv D:\out --csvf usn-paths.csv
Import-Csv D:\out\usn-paths.csv |
  Where-Object { $_.UpdateReasons -match 'BasicInfoChange|FileDelete|DataTruncation' } |
  Sort-Object UpdateTimestamp | Select-Object -First 40
```

False-positive note: the journal is capped by `MaximumSize` and discards oldest records first, so a short span on a busy server is normal. Read the journal ID and size before treating a short span as deletion; a `deletejournal` followed by `createjournal` is the actual signal.

## Class 4 — Event channel bookends and clear records

Expected hit: a channel whose oldest surviving record predates the incident, and no 1102/104 inside the window. A clear record that *is* the oldest survivor means the channel was refreshed.

```powershell
$logs = 'Security','System','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational'
foreach ($l in $logs) {
  $old = Get-WinEvent -LogName $l -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
  $cfg = Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Log = $l; Oldest = $old.TimeCreated; OldestId = $old.RecordId
    Clear = ($old.Id -in 1102,104,1100); Count = $cfg.RecordCount
    MaxBytes = $cfg.MaximumSizeInBytes; Mode = $cfg.LogMode
  }
}
```

False-positive note: an auto-archived channel (`LogMode` with retention) rolls at its size limit and starts mid-history with no 1102. Compare `MaximumSizeInBytes` and `RecordCount` against neighbouring hosts of the same build before alleging a clear.

## Class 5 — Record-ID continuity inside a channel

Expected hit: `RecordId` increasing by one for every event in the channel. A gap with no clear record is removal by an editor, not a native clear.

```powershell
Get-WinEvent -LogName Security -MaxEvents 20000 |
  Sort-Object RecordId |
  ForEach-Object -Begin { $prev = $null } -Process {
    if ($null -ne $prev -and $_.RecordId -ne $prev + 1) {
      [pscustomobject]@{ GapFrom = $prev; GapTo = $_.RecordId; At = $_.TimeCreated }
    }
    $prev = $_.RecordId
  }
```

False-positive note: channels written by multiple sessions and channels restored from a backup can present legitimate jumps, and 32-bit wraparound appears as a single large backwards step. Corroborate a gap with `$LogFile` or `$J` entries showing the EVTX file being written by an unexpected process.

## Class 6 — Execution-history void

Expected hit: prefetch entries covering the incident window for the binaries that ran, matching the USN and event-log timeline. A void while other execution evidence continues is the finding.

```powershell
Get-ChildItem "D:\evidence\HOST01\Windows\Prefetch" -Filter *.pf |
  Select-Object Name, Length, CreationTimeUtc, LastWriteTimeUtc | Sort-Object CreationTimeUtc
Get-Item "D:\evidence\HOST01\Windows\System32\config\SYSTEM" | Select-Object FullName, Length
```

False-positive note: Windows Server installs commonly disable prefetch, and SSD-only builds may keep only a subset. Read `EnablePrefetcher` from the SYSTEM hive before interpreting a sparse prefetch directory, and remember prefetch is capped at 1024 entries.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, next to every anti-forensic finding, which artifacts were available and which were absent by design; a conclusion drawn from a class the platform never wrote is not a finding.
