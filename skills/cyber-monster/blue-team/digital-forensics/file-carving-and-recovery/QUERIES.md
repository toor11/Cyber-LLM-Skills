# Artifacts and Queries

> Sub-skill: [`file-carving-and-recovery`](SKILL.md) | Family: **Digital Forensics**

Artifact-location and recovery checks owned by `file-carving-and-recovery`, grouped by recovery route. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Every command reads a copy and writes to a separate output volume; nothing is carved onto the evidence image or run from a mounted device.

## Class 1 — Recovery route gate (metadata before carving)

Expected hit: a defensible reason carving is needed. If metadata recovery can satisfy the question, carving is a precision loss you do not have to accept.

```bash
START=${START:-2048}
IMG=/cases/16/disk.dd
# Deleted entries still carrying an inode or record number:
fls -r -d -o "$START" "$IMG" | head -60
# Allocation state for one candidate record:
istat -o "$START" "$IMG" 42 | sed -n '1,25p'
```

False-positive note: `fls -d` lists names from directory residue even when the inode has no recoverable pointers (common on ext4). A listed name is a lead; only a successful `icat` or record extraction is a recovery.

## Class 2 — NTFS metadata recovery (resident and non-resident)

Expected hit: records with the in-use flag cleared whose `$DATA` is intact — resident content extractable directly, non-resident content recoverable while `$Bitmap` still shows its clusters free.

```powershell
MFTECmd.exe -f "D:\cases\16\$MFT" --csv D:\out --csvf mft_unallocated.csv --at --dr
Import-Csv D:\out\mft_unallocated.csv |
  Where-Object { $_.InUse -eq $false -and $_.FileSize -gt 0 } |
  Sort-Object Created0x10 -Descending |
  Select-Object EntryNumber, SequenceNumber, ParentPath, FileName, FileSize, Created0x30 -First 40
Get-ChildItem D:\out\Resident -ErrorAction SilentlyContinue |
  Select-Object Name, Length | Select-Object -First 20
```

False-positive note: `--dr` dumps resident streams into a `Resident` subdirectory named by entry, sequence and attribute; a record whose sequence number has advanced describes a *previous* file at that entry. Report entry and sequence together or the attribution is wrong.

## Class 3 — Targeted signature carving

Expected hit: candidates of the one type under investigation, with a measurable false-positive rate from the same signature set on a benign region.

```bash
IMG=/cases/16/disk.dd; OUT=/cases/16/carve; mkdir -p "$OUT"

# Scalpel: explicit, auditable signature config — one type only.
grep -E '^\s*jpg' /etc/scalpel/scalpel.conf > "$OUT/jpeg.conf" 2>/dev/null || \
  printf 'jpg y 20000000 \\xff\\xd8\\xff\\xe0\\xff\\xd9\n' > "$OUT/jpeg.conf"
scalpel -c "$OUT/jpeg.conf" -o "$OUT/out" "$IMG"

# Foremost with the same narrow set, for an independent second opinion.
foremost -c "$OUT/jpeg.conf" -t jpg -i "$IMG" -o "$OUT/foremost" -q

find "$OUT" -type f -name '*.jpg' | wc -l
```

False-positive note: carvers disagree on the same image, and PhotoRec's behaviour on synthetic test data has been reported as markedly weaker than Foremost and Scalpel on fragmented sets. Two carvers agreeing on a candidate raises confidence; one carver's count alone does not.

## Class 4 — Structural validation of carved output

Expected hit: a per-candidate verdict of valid or fragment, with the validation method named. An unvalidated carve is a byte-range claim, not a recovery.

```bash
python3 - <<'PY_CARVE'
import hashlib
import pathlib as paths
from PIL import Image
for p in sorted(paths.Path("/cases/16/carve").rglob("*.jpg")):
    carved = p.read_bytes()
    try:
        with Image.open(p) as im:
            im.verify()
        size, dims = len(data), Image.open(p).size
        print("VALID", p.name, size, dims, hashlib.sha256(data).hexdigest()[:16])
    except Exception as exc:
        print("FRAGMENT", p.name, len(data), type(exc).__name__)
PY_CARVE
```

```bash
# Container formats: internal consistency beats a footer match.
unzip -t carved.docx 2>&1 | tail -3
pdfinfo carved.pdf 2>&1 | head -8
```

False-positive note: `PIL.verify()` checks structure only; a JPEG with a correct header and a garbage scan can still pass on some builds. Decode the image fully and inspect it before describing content.

## Class 5 — Feature extraction over unallocated space

Expected hit: an inventory of what feature classes exist in a region without regard to filesystem structure — useful for choosing which types to carve, not for proving a file was present.

```bash
bulk_extractor -o /cases/16/bx -x all -e jpeg_carved -e exif -e email \
  /cases/16/disk.dd 2>&1 | tail -5
ls /cases/16/bx | head -20
```

False-positive note: `bulk_extractor` reports features independent of allocation, so hits include content from live, allocated files elsewhere on the volume. It is an inventory, never an attribution.

## Class 6 — Corroboration for a carved candidate

Expected hit: a journal, change-log or application record that ties the byte range or the content hash to a path and a time.

```powershell
# USN records for the likely original path or a matching size.
MFTECmd.exe -f "D:\cases\16\$J" -m "D:\cases\16\$MFT" --csv D:\out --csvf usn.csv
Import-Csv D:\out\usn.csv |
  Where-Object { $_.UpdateReasons -match 'FileDelete|FileRename' } |
  Select-Object UpdateTimestamp, Name, UpdateReasons | Sort-Object UpdateTimestamp | Select-Object -Last 30
```

False-positive note: a journal entry naming a deleted path does not prove the carved bytes are that file. Corroboration requires an allocation overlap or a hash match, not a name coincidence.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, for every carved artifact, the carver and version, the byte range, the validation verdict and any corroborating record; a candidate missing those four is not reportable.
