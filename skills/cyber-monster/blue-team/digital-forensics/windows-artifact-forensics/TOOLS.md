# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-artifact-forensics`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for a Windows host examination. This matrix is the orchestration layer: each tool belongs to a branch whose depth lives in a child skill. Confirm flags with `<tool> --help`; the Zimmerman set shares a `--csv`/`--csvf` grammar but differs in scoping flags.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `KAPE` and `Velociraptor` | `KAPE.exe --tsource C: --tdest E:\out --target !SANS_Triage`, or the `Windows.Triage.Targets` artifact | Triage collection whose omissions you can enumerate afterwards; the KAPE-target artifact was renamed on Velociraptor 0.75+, so confirm the name | Windows, Cross-platform |
| `PECmd` and `SrumECmd` | `PECmd.exe -d <PrefetchDir> --csv <out> --csvf prefetch.csv` and `SrumECmd.exe -d <sru> -r <SOFTWARE> --csv <out>` | Execution timing with volume identity, and per-SID application and network resource use | Windows |
| `RECmd` | `RECmd.exe -d <hiveDir> --bn BatchExamples\Kroll_Batch.reb --csv <out>` | Bulk hive extraction with transaction-log replay | Windows |
| `MFTECmd` | `MFTECmd -f '$MFT' --csv <out>` and `-f '$J' -m '$MFT'` | NTFS metadata and journal with path resolution | Windows |
| `EvtxECmd` | `EvtxECmd.exe -d <logDir> --csv <out> --csvf events.csv` | Whole-directory EVTX parsing into one reviewable table | Windows |
| `LECmd` / `JLECmd` | `LECmd.exe -d <Recent> --csv <out>`, then `JLECmd.exe -d <AutomaticDestinations>` | LNK targets with volume serials and jump-list destinations for user-intent and removable-media questions | Windows |

The four branch skills each carry the deeper tool set for their own artefact class.

## Minimal Script Shape

The shape below builds the readiness matrix, refuses to interpret an absent or stale source, and performs one cross-artefact join. It mirrors what a reviewer needs to audit the conclusion without re-running every parser.

```bash
#!/usr/bin/env bash
# win-readiness.sh — matrix first, then a single corroborated join.
set -euo pipefail
ROOT="${1:?usage: $0 <triage-root> [baseline-host-root]}"
BASE="${2:-}"; OUT="${3:-./derived}"; mkdir -p "$OUT"
CFG="$ROOT/Windows/System32/config"

mark () { # mark <name> <path> <logpath-or-empty>
  local n="$1" p="$2" l="${3:-}"
  if [ ! -e "$p" ]; then echo "$n|ABSENT|no claim possible"
  elif [ -n "$l" ] && [ ! -e "$l" ]; then echo "$n|STALE RISK|logs missing: $l"
  else echo "$n|USABLE|ok"; fi
}

{
  mark "SYSTEM hive"   "$CFG/SYSTEM"        "$CFG/SYSTEM.LOG1"
  mark "SOFTWARE hive" "$CFG/SOFTWARE"      "$CFG/SOFTWARE.LOG1"
  mark "NTUSER.DAT"    "$ROOT/Users"        ""
  mark "Prefetch"      "$ROOT/Windows/Prefetch" ""
  mark "SRUDB.dat"     "$ROOT/Windows/System32/sru/SRUDB.dat" ""
  mark "Amcache.hve"   "$ROOT/Windows/AppCompat/Programs/Amcache.hve" ""
  mark "MFT"           "$ROOT/\$MFT"        "$ROOT/\$Extend/\$UsnJrnl:\$J"
} | tee "$OUT/readiness.txt"

# Refuse to state an execution claim without an execution-capable pair.
grep -q '^Prefetch|USABLE' "$OUT/readiness.txt" || echo "NOTE: Prefetch unusable -> execution claims need 4688/Sysmon"
grep -q '^SRUDB.dat|USABLE' "$OUT/readiness.txt" || echo "NOTE: SRUM unusable -> no per-SID attribution available"

PECmd.exe -d "$ROOT/Windows/Prefetch" --csv "$OUT" --csvf prefetch.csv -q >/dev/null
[ -e "$ROOT/Windows/System32/sru/SRUDB.dat" ] && \
  SrumECmd.exe -d "$ROOT/Windows/System32/sru" -r "$CFG/SOFTWARE" --csv "$OUT" -q >/dev/null

# One join, printed with the claim class attached to every row.
awk -F, 'NR>1 {print $1","$NF}' "$OUT/prefetch.csv" 2>/dev/null | head -20 > "$OUT/exec_candidates.txt"
if [ -n "$BASE" ]; then
  diff <(sort "$OUT/exec_candidates.txt") <(sort "$BASE/exec_candidates.txt") \
    | grep '^<' | sed 's/^< /NOVEL TO THIS HOST: /' | tee "$OUT/novel_exec.txt" || true
fi
```

## Notes That Prevent Wrong Runs

- `KAPE` targets are a menu, not a guarantee. Enumerate what arrived against what the target claims, and treat every uncollected artefact as a coverage gap in the report.
- Velociraptor renamed `Windows.KapeFiles.Targets` to `Windows.Triage.Targets`, and the KAPE-targets artifacts moved into `Server.Import.Extras`. A missing artifact is usually a namespace move rather than a collection failure.
- The `PECmd` prefetch reader resolves the volume serial at a fixed offset within the prefetch file. When correlating removable-media execution, read the serial from the parsed output rather than assuming a layout.
- `EvtxECmd` and Chainsaw/Hayabusa answer different questions: the first normalises, the second matches rules. Keep the normalised output so a zero-hit rule run can be distinguished from an empty log.
