# Evidence Extraction Artifacts and Queries

> Sub-skill: [`windows-artifact-forensics-file-system-artifacts`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `windows-artifact-forensics-file-system-artifacts`. Each class names the NTFS structure being read, the parser invocation, and the comparison that turns records into a finding. `MFTECmd` handles `$MFT`, `$J`, `$LogFile`, `$Boot`, `$Secure:$SDS` and `$I30` and detects the type from content.

## Class 1 — Volume source set and coverage boundary

Expected hit: all three metadata files from the same volume with the journal's oldest and newest USN recorded. A journal whose oldest record postdates the incident cannot support an absence claim.

```bash
MFTECmd -f '$MFT'   --csv ./out --csvf mft.csv   >/dev/null
MFTECmd -f '$J'     -m '$MFT' --csv ./out --csvf usn.csv >/dev/null
awk -F, 'NR>1 {print $2}' ./out/usn.csv | sort -n | sed -n '1p;$p'   # USN range held
```

False-positive note: collecting `$J` without `$MFT` leaves `ParentPath` empty, so every record resolves to an unknown directory and the timeline loses its path dimension. Always pair them from the same volume and the same acquisition.

## Class 2 — The two timestamp sets on one record

Expected hit: per-record `$SI` and `$FN` created, modified, accessed and changed times, with the delta and subsecond precision visible.

```bash
MFTECmd -f '$MFT' --csv ./out --csvf mft.csv >/dev/null
awk -F, 'NR==1{for(i=1;i<=NF;i++)h[$i]=i} NR>1 &&
  $h["Created0x10"] < $h["Created0x30"] {print $h["EntryNumber"], $h["ParentPath"], $h["FileName"]}' \
  ./out/mft.csv | head -40
```

False-positive note: installers and archive extractors write `$SI` times from stored values and regularly produce `$SI` earlier than `$FN`. Require a matching parent-directory install burst or a journal metadata-only record before escalating.

## Class 3 — Journal reason-mask analysis

Expected hit: records whose reason is exactly `BasicInfoChange` (often with `Close`) and whose file reference has no nearby `DataOverwrite`, `DataExtend`, `FileCreate` or rename.

```bash
awk -F, 'NR>1 && $0 ~ /BasicInfoChange/ && $0 !~ /DataOverwrite|DataExtend|FileCreate|Rename/ \
  {print $2,$4,$5}' ./out/usn.csv | sort -u | head -40
```

False-positive note: `attrib +H`, `+R`, compression toggles and EFS state changes produce the same bare metadata record. Rank by the `$SI`/`$FN` delta and keep the attribute toggles in the output rather than discarding them, so the ranking is auditable.

## Class 4 — Deletion and name reuse

Expected hit: a `FileDelete` on a file reference followed by a `FileCreate` reusing the same name under the same parent.

```bash
awk -F, 'NR>1 && ($0 ~ /FileDelete/ || $0 ~ /FileCreate/) {print $2,$4,$5}' ./out/usn.csv |
  sort -u | awk '{c[$3]++} END {for (n in c) if (c[n]>1) print n}' | head -20
```

False-positive note: log rotation, temp-file churn and installer staging reuse names constantly. Restrict the scan to directories that matter in the case, and correlate with the file's `$MFT` allocation state before calling it concealment.

## Class 5 — Recycle bin attribution

Expected hit: `$I` records pairing an original path, a deletion time and the owning SID, with the matching `$R` payload still present for content recovery.

```powershell
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -Filter '$I*' -ErrorAction SilentlyContinue |
  ForEach-Object { $b = [IO.File]::ReadAllBytes($_.FullName)
    [pscustomobject]@{ Sid = $_.Directory.Name; Size = [BitConverter]::ToInt64($b,8)
                       Deleted = [datetime]::FromFileTime([BitConverter]::ToInt64($b,16)) } } |
  Sort-Object Deleted -Descending | Select-Object -First 20
```

False-positive note: an empty recycle bin is often policy, not evidence. Files deleted by applications bypass the shell and never appear here, so absence proves nothing about deletion by non-shell means.

## Class 6 — `$LogFile` reconstruction

Expected hit: metadata transactions covering a window the journal no longer holds, reconstructed as ordered operations on a file reference.

```bash
MFTECmd -f '$LogFile' --csv ./out --csvf logfile.csv >/dev/null
awk -F, 'NR>1 {print $2,$3,$4}' ./out/logfile.csv | head -40
```

False-positive note: `$LogFile` is a small circular write-ahead log and wraps quickly on a busy volume. Its earliest entry is a hard coverage boundary, not the start of activity, and quoting it as such understates the timeline.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the USN coverage range and the `$MFT` record count beside every finding that depends on an absence.
