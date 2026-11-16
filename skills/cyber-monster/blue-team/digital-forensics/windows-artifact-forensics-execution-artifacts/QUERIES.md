# Evidence Extraction Artifacts and Queries

> Sub-skill: [`windows-artifact-forensics-execution-artifacts`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `windows-artifact-forensics-execution-artifacts`. Each class names one artefact, the parser invocation, and the filter that converts output into a claim of the right class — execution, identity, presence or per-user attribution. Confirm flags with `<tool> --help`; `PECmd`, `AmcacheParser`, `AppCompatCacheParser`, `SrumECmd` and `RECmd` share a largely consistent option grammar.

## Class 1 — Collection prerequisites

Expected hit: every artefact present with its dependency. Prefetch needs its directory and a `SysMain` state; SRUM needs `SRUDB.dat` plus the `SRU` transaction logs and the SOFTWARE hive; Amcache and ShimCache need the hive plus `.LOG1`/`.LOG2`.

```powershell
Get-Service SysMain | Select-Object Name, Status, StartType
Get-ChildItem C:\Windows\System32\sru -Force | Select-Object Name, Length
Get-ChildItem C:\Windows\AppCompat\Programs -Force -ErrorAction SilentlyContinue | Select-Object Name, Length
```

False-positive note: a stopped `SysMain` on a running host does not mean the host never prefetched — the service can have been stopped after the incident, and server SKUs disable it by default. Check the service start type and the OS SKU before drawing conclusions from an empty Prefetch directory.

## Class 2 — Prefetch execution timing

Expected hit: one row per `.pf` with source filename, run count and the last-run timestamps, plus the volume serial and device path.

```powershell
PECmd.exe -d "C:\case\C\Windows\Prefetch" --csv "C:\case\out" --csvf prefetch.csv
Import-Csv C:\case\out\prefetch.csv |
  Select-Object SourceFilename, RunCount, LastRunTimestamp, PreviousRun0..PreviousRun6,
                VolumeSerialNumber, ExecutablePath | Format-Table -Wrap
```

False-positive note: Prefetch records the image load, not the process lifetime, and a loader that loads and immediately exits can appear once with a run count of one. A run count above one with tight intervals is the shape of a scheduled task, not of interactive use.

## Class 3 — Amcache identity and hash

Expected hit: a path, SHA-1, size, publisher and first-observed timestamp for each inventoried image. The hash is the pivotable field.

```powershell
AmcacheParser.exe -f "C:\case\C\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\case\out" --csvf amcache.csv
Import-Csv C:\case\out\amcache.csv | Where-Object { $_.FileId } |
  Select-Object Path, SHA1, FileSize, Publisher, LinkDate | Format-Table -Wrap
```

False-positive note: the SHA-1 in Amcache is computed over only the first portion of a large file, so it will not match a full-file hash from `Get-FileHash` for anything above that threshold. Compare against a tool that hashes the same prefix, or treat a mismatch on a large file as expected.

## Class 4 — ShimCache presence

Expected hit: paths with last-modification times and, on modern Windows, the trailing execution flag that recent `AppCompatCacheParser` builds decode.

```powershell
AppCompatCacheParser.exe --SYSTEM "C:\case\C\Windows\System32\config\SYSTEM" --csv "C:\case\out" --csvf shimcache.csv
Import-Csv C:\case\out\shimcache.csv | Select-Object Path, LastModified, Executed | Format-Table
```

False-positive note: on Windows 10 and later the timestamp column is the file's last-modification time, not the time of shimming and not the time of execution. Reporting it as an execution time is the most common error in this class; the `Executed` flag is corroboration, not proof.

## Class 5 — SRUM per-SID resource use

Expected hit: per-application rows with the executing SID, foreground and background bytes, and network bytes per interface, within roughly the last 30 to 60 days.

```powershell
SrumECmd.exe -d "C:\case\C\Windows\System32\sru" -r "C:\case\C\Windows\System32\config\SOFTWARE" --csv "C:\case\out"
Import-Csv C:\case\out\SRUM_AppResourceUseInfo.csv |
  Sort-Object BytesSent -Descending | Select-Object -First 20 -Property AppId, UserSid, BytesSent, BytesReceived
```

False-positive note: SRUM aggregation windows are not uniform and a dirty `SRUDB.dat` without its transaction logs may be repaired into a state missing recent rows. Record whether the logs were collected; a database parsed without them gives a partial timeline that reads like a quiet period.

## Class 6 — BAM and DAM last-execution

Expected hit: one FILETIME per path under `Services\bam\State\UserSettings\{SID}` and the equivalent DAM key, keyed to a SID resolvable through the SAM or the SOFTWARE hive.

```powershell
RECmd.exe -f "C:\case\C\Windows\System32\config\SYSTEM" --kn "ControlSet001\Services\bam\State\UserSettings" --csv "C:\case\out" --csvf bam.csv
Import-Csv C:\case\out\bam.csv | Select-Object KeyPath, ValueName, ValueData | Format-Table -Wrap
```

False-positive note: BAM retains a single last-execution value per path and overwrites it, so it proves recency rather than occurrence count. It also excludes some process classes by design, so an absent entry is not proof of non-execution.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the artefact retention boundary (oldest retained entry) in every report that relies on an absence.
