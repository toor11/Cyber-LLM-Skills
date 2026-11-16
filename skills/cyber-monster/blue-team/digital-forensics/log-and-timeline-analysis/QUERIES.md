# Artifacts and Queries

> Sub-skill: [`log-and-timeline-analysis`](SKILL.md) | Family: **Digital Forensics**

Extraction and filter commands owned by `log-and-timeline-analysis`, grouped by timeline source. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Extraction runs against image copies and writes storage files outside the evidence volume; no source log is ever edited to improve an ordering.

## Class 1 — Extraction gate (once per case)

Expected hit: a storage file whose extraction report names the parsers that ran and the warnings they raised. The extraction fixes the ceiling on everything later, so it is run once and kept.

```bash
CASE=/cases/31; mkdir -p "$CASE/timeline"
log2timeline.py --storage-file "$CASE/timeline/case.plaso" "$CASE/disk.dd"
pinfo.py "$CASE/timeline/case.plaso" | tee "$CASE/timeline/extraction-report.txt"
grep -Ei 'warn|error|unsupported' "$CASE/timeline/extraction-report.txt" | head -20
```

False-positive note: warnings are not failures — an unsupported artifact type is a coverage statement, not an error. What matters is recording which artifacts were parsed, so a later "nothing there" can be attributed to the parser rather than to the evidence.

## Class 2 — Windowed export with timestamp semantics retained

Expected hit: rows in UTC carrying `timestamp_desc` and `source`, so each row's time is interpretable. Dropping `timestamp_desc` collapses creation and modification into one indistinct claim.

```bash
P=/cases/31/timeline/case.plaso; OUT=/cases/31/timeline
psort.py -q -o dynamic --output_time_zone UTC \
  --fields datetime,timestamp_desc,source,hostname,user,message \
  -w "$OUT/window.csv" "$P" "date > '$START' AND date < '$END'"
head -5 "$OUT/window.csv"

# Centred slice around one anchor event, quickest way to pivot.
psort.py -q -o dynamic --output_time_zone UTC --slice "$ANCHOR" --slice_size 30 \
  -w "$OUT/slice.csv" "$P"
```

False-positive note: `--slice_size` is in minutes, and the default slice is five minutes either side. A slice that looks empty usually means the anchor was given in local time rather than the UTC the storage file uses.

## Class 3 — Filesystem-only timeline from a bodyfile

Expected hit: MACB flags and four epoch values per record, with a statement about whether the filesystem records creation time at all. Cheaper than a super timeline for a single-file question.

```bash
CASE=/cases/31; START_SECTOR=2048
fls -r -m / -o "$START_SECTOR" "$CASE/disk.dd" > "$CASE/timeline/body.txt"
mactime -b "$CASE/timeline/body.txt" -d -y 2026-11-01..2026-11-14 \
  > "$CASE/timeline/fs-utc.csv"
awk -F, 'NR>1 && $3=="" {n++} END {print "records_with_no_creation_time:", n+0}' "$CASE/timeline/fs-utc.csv"
```

False-positive note: a zero creation time means the filesystem did not record it (common on ext4 depending on TSK version, and on some non-native filesystems), not that the file was created at the epoch. Counting them is a coverage check, not a finding.

## Class 4 — Journal and event-log ordering with sequence numbers

Expected hit: rows carrying the source's own ordered identifier alongside its timestamp, so same-second ties can be resolved without relying on the clock.

```bash
JOURNAL_DIR=/mnt/case/var/log/journal
journalctl --directory="$JOURNAL_DIR" --utc --since "$START" --until "$END" -o json \
| jq -r '[.__REALTIME_TIMESTAMP, .__SEQNUM, ._COMM, .MESSAGE] | @tsv' | head -40
```

```powershell
# EVTX: keep EventRecordId so gaps and ties are visible.
Get-WinEvent -Path D:\cases\31\Security.evtx -Oldest |
  Select-Object -First 200 RecordId, TimeCreated, Id, ProviderName |
  Sort-Object RecordId | Format-Table -AutoSize
```

False-positive note: `__SEQNUM` is per-journal-file and restarts across rotations, and `EventRecordId` is per-channel. Comparing sequence numbers across files or channels produces a false ordering.

## Class 5 — Baseline density for the same duration

Expected hit: a per-source event count for a quiet window of the same length as the incident window. Without it, a burst has no meaning.

```bash
P=/cases/31/timeline/case.plaso
psort.py -q -o dynamic --output_time_zone UTC --fields datetime,source \
  -w /cases/31/timeline/baseline.csv "$P" \
  "date > '$BASE_START' AND date < '$BASE_END'"
awk -F, 'NR>1 {c[$2]++} END {for (s in c) printf "%8d %s\n", c[s], s}' \
  /cases/31/timeline/baseline.csv | sort -rn | head -15
```

False-positive note: a baseline taken from a different day of the week or from a maintenance window is not comparable. Pick a quiet window with the same workload profile, and say which window you used.

## Class 6 — Clock-state verification

Expected hit: evidence of whether the host's clock was disciplined and whether it jumped inside the window. Skew is the first hypothesis for any cross-source disagreement.

```bash
EVIDENCE=/mnt/case
journalctl --directory="$EVIDENCE/var/log/journal" --utc -o short-iso \
  _COMM=systemd-timesyncd --no-pager 2>/dev/null | tail -20
journalctl --directory="$EVIDENCE/var/log/journal" --utc -o short-iso \
  -g 'time (jump|change)|Time has been changed' --no-pager 2>/dev/null | tail -20
```

False-positive note: a time change logged at boot is normal initial synchronisation; the finding is a change inside the incident window, especially one that moves the clock backwards.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, for every timeline claim, the storage file's extraction report, the UTC window, and the source's own ordered identifier where one exists; a sequence claim without those is not reviewable.
