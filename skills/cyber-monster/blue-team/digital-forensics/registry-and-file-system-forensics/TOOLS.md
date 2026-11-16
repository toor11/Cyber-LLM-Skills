# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`registry-and-file-system-forensics`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for joining registry and NTFS metadata into one timeline. Confirm options with `<tool> --help`; `MFTECmd` detects artefact type from content and `rla` is single-purpose transaction-log replay.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `fls` / `fsstat` (Sleuth Kit) | `fsstat -o <offset> image.dd` then `fls -r -m / image.dd > bodyfile` | Establish the filesystem type and a filesystem-level bodyfile for cross-checking | Cross-platform |
| `rla` | `rla -f SYSTEM -l ./config -o ./clean` | Replay `.LOG1`/`.LOG2` into a clean hive before any key is read | Windows |
| `RECmd` | `RECmd.exe -d ./clean --bn BatchExamples\Kroll_Batch.reb --csv ./out` | Bulk key and value extraction with key timestamps | Windows |
| `MFTECmd` (`$J` + `$MFT`) | `MFTECmd -f '$J' -m '$MFT' --csv ./out --csvf usn.csv` | Journal records with paths rewound through directory history | Windows |
| `MFTECmd` (`$LogFile`) | `MFTECmd -f '$LogFile' --csv ./out --csvf logfile.csv` | Metadata transactions older than the journal tail, including a rename the journal no longer holds | Windows |
| `regipy` | `regipy-dump <hive> -o ./out.json` | Programmatic hive parsing with transaction-log support on non-Windows hosts | Cross-platform |

## Minimal Script Shape

The shape below establishes the filesystem, replays hives, prints both boundaries, and emits a provenance-tagged join. Read-only against the evidence copy.

```bash
#!/usr/bin/env bash
# reg-fs-timeline.sh — boundaries first, provenance on every row.
set -euo pipefail
IMG_OFFSET="${1:?usage: $0 <image> <partition-offset> <config-dir> <\$MFT> <\$J>}"
IMG="$0"; shift 2
CFG="${1:?config dir}"; MFT="${2:?MFT}"; J="${3:?J}"; OUT="${4:-./derived}"; mkdir -p "$OUT"

# 0. Filesystem precondition: the journal branch only exists on NTFS.
FS=$(fsstat -o "$IMG_OFFSET" "$IMG" 2>/dev/null | awk -F': *' '/^File System Type/{print $2; exit}')
echo "filesystem: ${FS:-unknown}" | tee "$OUT/precondition.txt"
case "${FS:-}" in
  NTFS*) echo "journal branch: APPLICABLE" | tee -a "$OUT/precondition.txt" ;;
  *)     echo "journal branch: NOT APPLICABLE -> stop" | tee -a "$OUT/precondition.txt"; exit 3 ;;
esac

# 1. Replay hives and record which were dirty.
for h in SYSTEM SOFTWARE SAM SECURITY; do
  [ -f "$CFG/$h" ] || continue
  if [ -f "$CFG/$h.LOG1" ] || [ -f "$CFG/$h.LOG2" ]; then
    rla -f "$h" -l "$CFG" -o "$OUT/clean" >/dev/null 2>&1 || echo "REPLAY FAILED: $h" >> "$OUT/gaps.txt"
  else
    echo "STALE: $h has no logs" >> "$OUT/gaps.txt"
  fi
done

# 2. Filesystem boundary.
MFTECmd -f "$J" -m "$MFT" --csv "$OUT" --csvf usn.csv -q
awk -F, 'NR>1 {print $2}' "$OUT/usn.csv" | sort -n | sed -n '1p;$p' | paste -sd'..' - > "$OUT/usn_range.txt"
echo "journal coverage: $(cat "$OUT/usn_range.txt")" | tee -a "$OUT/precondition.txt"

# 3. Provenance-tagged export: no row without its source system.
{ awk -F, 'NR>1 && $0 ~ /FileCreate|FileDelete/ {print "NTFS|"$2"|"$5}' "$OUT/usn.csv"
  awk -F, 'NR>1 {print "REG|"$(NF-1)"|"$NF}' "$OUT/keys.csv" 2>/dev/null
} | sort -t'|' -k3 > "$OUT/timeline_tagged.txt"
wc -l < "$OUT/timeline_tagged.txt"
```

## Notes That Prevent Wrong Runs

- `fsstat` needs the correct partition offset; run it against the base image without the offset and it will either fail or report the wrong filesystem, invalidating every downstream branch decision.
- `rla` writes a new hive. Keep the original dirty hive and its logs as evidence, and hash both the original and the replayed copy.
- `MFTECmd -f '$J'` without `-m '$MFT'` produces empty paths. Both must come from the same volume and the same acquisition.
- `$I30` parsing recovers directory index entries including slack; use it when a filename is suspected but absent from the live index, and treat recovered names as index remnants rather than confirmed files.
