# Evidence Extraction Artifacts and Queries

> Sub-skill: [`registry-and-file-system-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `registry-and-file-system-forensics`. Each class names the structure, the parser, and the boundary it must print before any absence is interpreted. Key-level interpretation lives in [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md); the timestomp differential in depth lives in [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md).

## Class 1 — Volume and source precondition

Expected hit: the filesystem type, the hive set with log presence, and the `$MFT` and `$J` availability. Non-NTFS volumes invalidate the journal branch entirely.

```bash
fsstat -o 2048 image.dd | sed -n '1,15p'          # NTFS / FAT / exFAT / other
ls -la --time-style=+ config/ | head -20          # hives and .LOG1/.LOG2 side by side
```

False-positive note: `fsstat` against the wrong partition offset reports a different filesystem, which then makes every NTFS conclusion invalid. Confirm the offset from the partition table before trusting the type.

## Class 2 — Hive state and transaction-log replay

Expected hit: a clean copy produced by replay, plus a record of which hives were dirty.

```bash
rla -f SYSTEM -l ./config -o ./clean
RECmd.exe -f ./clean/SYSTEM -kn "Select" --csv ./out --csvf select.csv
```

False-positive note: a hive whose base block sequence numbers agree can still be behind its logs if it was copied mid-flush. Treat "no logs collected" as a staleness risk regardless of the sequence numbers.

## Class 3 — Key timestamps with provenance

Expected hit: key paths, value data and `LastWrite` timestamps, tagged as registry-sourced.

```bash
RECmd.exe -d ./clean --bn "BatchExamples/Kroll_Batch.reb" --csv ./out --csvf keys.csv
awk -F, 'NR>1 {printf "REG|%s|%s|%s\n", $NF, $(NF-1), $2}' ./out/keys.csv | head -40
```

False-positive note: `LastWrite` updates when the key's own contents change and may not move when a subkey below it changes. An unchanged parent timestamp alongside a new child key is expected, not evidence that nothing changed.

## Class 4 — Journal lifecycle records

Expected hit: `FileCreate`, `FileDelete`, `Rename` and `BasicInfoChange` records with file references, parent references and timestamps.

```bash
MFTECmd -f '$J' -m '$MFT' --csv ./out --csvf usn.csv -q
awk -F, 'NR>1 && ($0 ~ /FileCreate/ || $0 ~ /FileDelete/) {print $2,$4,$5}' ./out/usn.csv | sort -u | head -40
```

False-positive note: without `-m '$MFT'` the `ParentPath` column is empty and the lifecycle records cannot be placed in a directory. An empty path column is a parse configuration issue, not a file that lived nowhere.

## Class 5 — Timestamp-set disagreement

Expected hit: `$MFT` rows where `$SI` and `$FN` disagree, with subsecond precision visible so a second-precision tool is distinguishable from an ordinary write.

```bash
MFTECmd -f '$MFT' --csv ./out --csvf mft.csv -q
awk -F, 'NR==1{for(i=1;i<=NF;i++)h[$i]=i} NR>1 && $h["Created0x10"] < $h["Created0x30"]' ./out/mft.csv | head -30
```

False-positive note: installers, archive extractors and backup restores preserve stored timestamps and routinely produce `$SI` earlier than `$FN`. Require a matching journal metadata-only record before escalating.

## Class 6 — Pre-change state from `$LogFile`

Expected hit: ordered metadata transactions for a window the journal no longer retains.

```bash
MFTECmd -f '$LogFile' --csv ./out --csvf logfile.csv -q
awk -F, 'NR>1 {print $2"|"$3"|"$4}' ./out/logfile.csv | sed -n '1,40p'
```

False-positive note: `$LogFile` is small and wraps fast on an active volume. Its earliest entry is a coverage boundary, not the start of activity, and quoting it as such truncates the timeline.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Print the filesystem type, the hive replay state and the journal USN range beside every finding built on an absence.
