# Artifacts and Queries

> Sub-skill: [`disk-forensics-and-artifacts`](SKILL.md) | Family: **Digital Forensics**

Artifact-location and extraction checks owned by `disk-forensics-and-artifacts`, grouped by storage layer. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Nothing here mounts evidence read-write, repairs an image, or writes onto the evidence volume; work from copies and keep every extracted file's digest.

## Class 1 — Container and integrity gate

Expected hit: a verified image and a known partition layout. A partition offset in sectors carried correctly into every later command is the precondition for every other class.

```bash
# Raw image: hash first, then read the partition table.
sha256sum disk.dd | tee disk.dd.sha256
mmls disk.dd
mmls -B disk.dd            # same table, sizes in bytes

# EWF: expose read-only, then treat the node as the device.
mkdir -p /mnt/ewf && ewfmount disk.E01 /mnt/ewf
mmls /mnt/ewf/ewf1
ewfverify -d sha256 disk.E01 | tail -5
```

False-positive note: an image whose hash differs from the acquisition hash is not an evidence problem to investigate, it is an image to re-acquire. Also note `mmls` reports the meta and unallocated slots alongside real partitions; taking the first line as the filesystem start yields a wrong `-o` and an empty listing.

## Class 2 — Filesystem identification and metadata

Expected hit: a filesystem type, block size and inode or MFT range, plus a record count that matches the volume's size for its block size.

```bash
START=2048
fsstat -o "$START" disk.dd
istat  -o "$START" disk.dd 42          # ext4 inode or NTFS MFT record 42
fls -r -p -o "$START" disk.dd | head -50
```

False-positive note: `fsstat` on an encrypted volume reports an unrecognised type rather than an error that names encryption. A volume that looks like random data at the expected offset should be treated as encrypted until the header says otherwise, not as wiped.

## Class 3 — Deleted entries and directory residue

Expected hit: deleted entries in `fls -d` output whose names survive and whose inode or record number can be resolved. An empty deleted list on a volume that clearly had files is a stop condition.

```bash
START=2048
fls -r -d -o "$START" disk.dd | head -80
fls -r -m / -o "$START" disk.dd > body.txt
mactime -b body.txt -d -y 2026-09-01..2026-09-30 > fs-timeline.csv
wc -l body.txt fs-timeline.csv
```

False-positive note: on ext4 the deleted inode usually has its extent entries zeroed and its size set to zero, so `fls` names a file that `icat` cannot extract. Reporting "deleted file found" from the name alone, without a successful extraction, overstates the evidence.

## Class 4 — NTFS record-level extraction

Expected hit: MFT records with the in-use flag, both timestamp sets, and resident data where present. This is the spine for any Windows volume question.

```powershell
# $MFT extracted from the image or a read-only mount.
MFTECmd.exe -f "D:\cases\14\$MFT" --csv D:\out --csvf mft_volume.csv --at
Import-Csv D:\out\mft_volume.csv |
  Where-Object { $_.InUse -eq $false } |
  Select-Object EntryNumber, ParentPath, FileName, FileSize, Created0x10, Created0x30 |
  Sort-Object Created0x10 -Descending | Select-Object -First 40
```

False-positive note: an unused MFT record whose sequence number has advanced describes a *previous* file at that record, not the current one. Report the entry and sequence together, and never join a stale record to a live path without checking the sequence.

## Class 5 — Allocation state for a candidate file

Expected hit: `$Bitmap` bits for the file's clusters showing free, with the clusters not reallocated to another file since. Whether the content survives is answered by reading those clusters, not by the bitmap.

```bash
# ext4: which blocks an inode claims, and whether they are still free.
START=2048
istat -o "$START" disk.dd 42 | sed -n '/Direct Blocks/,/Indirect/p'
icat -s -o "$START" disk.dd 42 > slack.bin     # slack space after logical end
ls -l slack.bin
```

False-positive note: `-s` returns slack, which contains the tail of a previous allocation, not the file's own content. Quoting slack bytes as "the deleted file" is a common and serious overstatement.

## Class 6 — Image-to-image comparison

Expected hit: identical hashes for two acquisitions of a quiescent device, and an error map naming the sectors that differ on a failing one.

```bash
# Compare two images sector by sector without writing either.
cmp -l disk-a.dd disk-b.dd | head -20
sha256sum disk-a.dd disk-b.dd
```

False-positive note: a live acquisition produces a different hash on every pass by definition — the volume changed. Only a dead-box acquisition supports an equality claim, and only a bad-sector map explains a difference on failing media.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, for every disk finding, the image hash, the partition offset used and the tool version; a finding that cannot be reproduced from those three is not reviewable.
