# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-artifact-forensics-file-system-artifacts`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for NTFS metadata analysis. `MFTECmd` detects the artefact type from the file's content, so the same binary handles `$MFT`, `$J`, `$LogFile`, `$Boot`, `$Secure:$SDS` and `$I30`. Confirm options with `MFTECmd --help`; flag names have changed between major versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `MFTECmd` (`$MFT`) | `MFTECmd -f '$MFT' --csv <out> --csvf mft.csv` | Per-record attribute timestamps including both the 0x10 and 0x30 sets | Windows |
| `MFTECmd` (`$J` with MFT) | `MFTECmd -f '$J' -m '$MFT' --csv <out> --csvf usn.csv` | Journal records with paths rewound through directory history | Windows |
| `MFTECmd` (`$LogFile`) | `MFTECmd -f '$LogFile' --csv <out> --csvf logfile.csv` | Metadata transactions older than the journal tail can reach | Windows |
| `MFTECmd` (`--vss`) | `MFTECmd -f '$MFT' --vss <shadow> --csv <out>` | Reads locked files and shadow copies through raw disk access | Windows |
| `fls` and `icat` (The Sleuth Kit) | `fls -r -m / image.dd > bodyfile`, then `icat image.dd <inode> > recovered.bin` | Filesystem-level listing with deleted entries, then content extraction by inode for hashing | Cross-platform |
| `RECmd` | `RECmd.exe -f <SYSTEM> --kn "ControlSet001\Control\FileSystem" --csv <out>` | Confirm NTFS settings that affect timestamp behaviour on the volume | Windows |

## Minimal Script Shape

The shape below produces the only defensible timestomp finding: a journal record with a metadata-only reason mask, joined to the MFT row for the same file reference, with the subsecond precision shown. Read-only.

```bash
#!/usr/bin/env bash
# ntfs-timestomp.sh — reason-mask gate joined to the SI/FN delta.
set -euo pipefail
MFT="${1:?usage: $0 \$MFT \$J \$LogFile}"
J="${2:?journal stream required}"
OUT="${3:-./derived}"; mkdir -p "$OUT"

# 0. Coverage boundary first: what window does this journal actually hold?
MFTECmd -f "$J" -m "$MFT" --csv "$OUT" --csvf usn.csv >/dev/null
awk -F, 'NR>1 {print $2}' "$OUT/usn.csv" | sort -n | sed -n '1p;$p' > "$OUT/usn_range.txt"
echo "journal USN range: $(paste -sd'..' "$OUT/usn_range.txt")"

# 1. MFT side: the two timestamp sets, with subsecond precision exposed.
MFTECmd -f "$MFT" --csv "$OUT" --csvf mft.csv >/dev/null

# 2. Journal side: metadata-only changes, exact mask, excluding data writes.
awk -F, 'NR>1 && $0 ~ /BasicInfoChange/ && $0 !~ /DataOverwrite|DataExtend|FileCreate|Rename/ \
  {print $2","$4","$5}' "$OUT/usn.csv" | sort -u > "$OUT/bare_bic.csv"

# 3. Join: only records where the MFT shows a matching SI/FN discrepancy.
while IFS=, read -r ts ref path; do
  hit=$(awk -F, -v r="$ref" 'NR>1 && $1==r && $0 ~ /\.0000000/ {print; exit}' "$OUT/mft.csv")
  [ -n "$hit" ] && printf 'rewrite=%s ref=%s path=%s\n  mft=%s\n' "$ts" "$ref" "$path" "${hit:0:180}"
done < "$OUT/bare_bic.csv" | head -60
```

## Notes That Prevent Wrong Runs

- `-m '$MFT'` is mandatory when parsing `$J` if you want `ParentPath`. Without it the column is empty and path-level conclusions are impossible.
- `$J` and `$MFT` must come from the same volume and the same acquisition. Mixing a journal from one capture with an MFT from another produces paths that never existed.
- `--vss` reads shadow copies through raw disk access; it still works against a mounted evidence volume, so use a write blocker or an image rather than a live system volume.
- `$LogFile` wraps quickly. Its earliest entry is a coverage boundary; never present it as the beginning of activity.
