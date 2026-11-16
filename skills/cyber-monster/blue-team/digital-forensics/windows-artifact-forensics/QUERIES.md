# Evidence Extraction Artifacts and Queries

> Sub-skill: [`windows-artifact-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `windows-artifact-forensics`, the flagship that decides which artefact branch can answer the question. Each class states the source, the readiness prerequisite, and the extraction. Branch-specific depth lives in the four child skills and is linked rather than duplicated.

## Class 1 — Readiness matrix

Expected hit: every artefact marked usable, stale-at-risk or absent, with the prerequisite recorded. This class gates every later one.

```powershell
$Root = "E:\out\C"
@(
  @{ S='SYSTEM hive';      P="$Root\Windows\System32\config\SYSTEM";        L=".LOG1" }
  @{ S='SOFTWARE hive';    P="$Root\Windows\System32\config\SOFTWARE";      L=".LOG1" }
  @{ S='Prefetch';         P="$Root\Windows\Prefetch";                       L=$null }
  @{ S='SRUDB.dat';        P="$Root\Windows\System32\sru\SRUDB.dat";         L=$null }
  @{ S='Amcache.hve';      P="$Root\Windows\AppCompat\Programs\Amcache.hve"; L=$null }
) | ForEach-Object {
  [pscustomobject]@{ Source=$_.S; Present=(Test-Path $_.P)
    LogsPresent=if ($_.L) { Test-Path ($_.P + $_.L) } else { $null } }
} | Sort-Object Source | Format-Table -AutoSize
```

False-positive note: `Test-Path` on a triage root succeeds for directories that exist but were collected empty. Check a file count or a size threshold, not just existence, before marking a source usable.

## Class 2 — Execution branch entry point

Expected hit: Prefetch load times joined to SRUM per-SID rows. Depth on claim classes is owned by [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md).

```powershell
PECmd.exe -d "$Root\Windows\Prefetch" --csv . --csvf prefetch.csv
SrumECmd.exe -d "$Root\Windows\System32\sru" -r "$Root\Windows\System32\config\SOFTWARE" --csv .
```

False-positive note: SRUM writes one CSV per table, so a directory-level import mixes application, network and energy tables together. Filter on the table name before joining.

## Class 3 — Registry branch entry point

Expected hit: hives with logs replayed and the live control set resolved. Key-level detail is owned by [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md).

```powershell
RECmd.exe -f "$Root\Windows\System32\config\SYSTEM" -kn "Select" --csv . --csvf select.csv
RECmd.exe -d "$Root\Windows\System32\config" --bn "BatchExamples\Kroll_Batch.reb" --csv .
```

False-positive note: `RECmd -d` on a directory silently skips hives it cannot open, including ones locked by another process on a live host. Count the hives in the input directory against the hives in the output before treating the extraction as complete.

## Class 4 — Event log branch entry point

Expected hit: channels exported with record identity intact, and the audit subcategory state recorded. EVTX internals are owned by [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md).

```powershell
wevtutil epl Security "E:\case\Security.evtx" /ow:true
EvtxECmd.exe -d "E:\case" --csv E:\derived --csvf events.csv
# Audit-subcategory state is captured by the event-log child; do not paraphrase it here:
# see ../windows-artifact-forensics-event-log-artifacts/QUERIES.md Class 2.
```

False-positive note: `Get-WinEvent` piped to `Export-Csv` loses the record ID and provider metadata. Always export the channel binary first and parse that, or the timeline cannot be tied back to a record.

## Class 5 — Filesystem branch entry point

Expected hit: `$MFT` with `$J` parsed together and the USN coverage range printed. Timestomp differentials are owned by [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md).

```bash
MFTECmd -f '$MFT' --csv ./derived --csvf mft.csv
MFTECmd -f '$J' -m '$MFT' --csv ./derived --csvf usn.csv
awk -F, 'NR>1 {print $2}' ./derived/usn.csv | sort -n | sed -n '1p;$p'
```

False-positive note: parsing `$J` without `-m $MFT` leaves every `ParentPath` empty. An empty path column is a parse configuration issue, not evidence that the files lived nowhere.

## Class 6 — User activity and removable media

Expected hit: LNK targets with volume serials, jump-list entries, and per-user mount history that ties a path to a device.

```powershell
LECmd.exe -d "C:\case\Users\alice\AppData\Roaming\Microsoft\Windows\Recent" --csv . --csvf lnk.csv
JLECmd.exe -d "C:\case\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv . --csvf jl.csv
Import-Csv lnk.csv | Select-Object SourceFile, TargetIDAbsolutePath, VolumeSerialNumber, TargetModified | Format-Table -Wrap
```

False-positive note: a LNK volume serial identifies a volume, not a physical device. Two cloned drives share a serial, and a reformatted volume keeps the serial it was assigned. Corroborate with `USBSTOR` before naming hardware.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the readiness state of every source cited, and the peer host used as baseline, beside every finding.
