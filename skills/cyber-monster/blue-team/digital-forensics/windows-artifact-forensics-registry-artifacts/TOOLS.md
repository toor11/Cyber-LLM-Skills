# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-artifact-forensics-registry-artifacts`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for offline registry analysis. Confirm options with `RECmd --help` and `rla -h`; the Zimmerman `Registry` library underpins `RECmd`, `AmcacheParser`, `AppCompatCacheParser` and `ShellBags Explorer`, so their transaction-log behaviour is consistent.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `RECmd` | `RECmd.exe -f <hive> --kn "<key>" --csv <out> --csvf out.csv` | Key-scoped extraction with automatic transaction-log replay | Windows |
| `RECmd` (batch) | `RECmd.exe -d <hiveDir> --bn BatchExamples\Kroll_Batch.reb --csv <out>` | Bulk extraction across all hives in a triage collection in one run | Windows |
| `RECmd` (no logs) | `RECmd.exe -f <hive> --nl ...` | Deliberately skip log replay, e.g. to compare dirty versus clean state | Windows |
| `rla` | `rla.exe -f <hive> -l <hiveDir>` | Replay `.LOG1`/`.LOG2` into a clean hive for tools that cannot replay | Windows |
| `regipy-process-transaction-logs` | `regipy-process-transaction-logs --hive-file <hive>` | Log replay on Linux and macOS where the Windows toolset is unavailable | Cross-platform |
| `Registry Explorer` and `reg query` | GUI open of a hive with the replay prompt, or `reg query "HKLM\...\Run"` for a live-host check | Visual verification of deleted keys and value slack, and a live-state read that carries no key timestamps | Windows |

## Minimal Script Shape

The shape below refuses to present a hive without its transaction logs as current, resolves the live control set, and publishes autostart values with a fleet-baseline flag. Read-only; it writes only into its own output directory.

```bash
#!/usr/bin/env bash
# reg-scope.sh — dirty-hive gate, control-set resolution, autostart delta.
set -euo pipefail
HIVE_DIR="${1:?usage: $0 <config-dir> [baseline.csv]}"
BASE="${2:-}"; OUT="${3:-./derived}"; mkdir -p "$OUT"

# 0. Dirty-hive gate.
for h in SYSTEM SOFTWARE SAM SECURITY DEFAULT; do
  [ -f "$HIVE_DIR/$h" ] || continue
  if [ ! -f "$HIVE_DIR/$h.LOG1" ] && [ ! -f "$HIVE_DIR/$h.LOG2" ]; then
    echo "STALE RISK: $h has no .LOG1/.LOG2 -> newest values may be absent" | tee -a "$OUT/gaps.txt"
  fi
  sha256sum "$HIVE_DIR/$h" >> "$OUT/hive_hashes.txt"
done

# 1. Live control set before any Services statement.
RECmd.exe -f "$HIVE_DIR/SYSTEM" -kn "Select" --csv "$OUT" --csvf select.csv -q
CUR=$(awk -F, 'NR>1 && $2=="Current" {print $3; exit}' "$OUT/select.csv" | tr -d '\r')
echo "live control set: $CUR" | tee "$OUT/controlset.txt"

# 2. Autostart extraction with key timestamps.
RECmd.exe -d "$HIVE_DIR" --bn "BatchExamples/Kroll_Batch.reb" --csv "$OUT" -q

# 3. Fleet-baseline delta on autostart values.
for f in "$OUT"/*.csv; do
  awk -F, 'NR>1 && $0 ~ /CurrentVersion\\Run|Winlogon/ {print $NF}' "$f"
done | sort -u > "$OUT/autostart_values.txt"

if [ -n "$BASE" ] && [ -f "$BASE" ]; then
  comm -23 "$OUT/autostart_values.txt" <(sort -u "$BASE") > "$OUT/autostart_novel.txt"
  echo "novel autostart values: $(wc -l < "$OUT/autostart_novel.txt")"
fi
cat "$OUT/autostart_novel.txt" 2>/dev/null || cat "$OUT/autostart_values.txt"
```

## Notes That Prevent Wrong Runs

- `RECmd` replays transaction logs automatically unless `--nl` is given. Supplying `--nl` produces a parse of the primary hive only, which is exactly the stale-state trap this skill warns about.
- `RegRipper` does not replay logs. Feed it a hive already cleaned by `rla` or by `RECmd --out`, never the original dirty hive.
- Replay into a new file and hash both: the dirty original and the replayed copy are different evidence objects and both belong in the case record.
- `--kn` matches key paths case-insensitively but requires the full path from the hive root; a partial path silently returns nothing rather than erroring.
