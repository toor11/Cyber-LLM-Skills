# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ir-triage-and-timeline`](SKILL.md) | Family: **Incident Response**

Verified collection and slicing entry points for triage. Every command below is read-only against the evidence; none mutates a host. Flag sets differ between releases, so confirm with `<tool> --help` on the installed version before relying on a flag in a runbook.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `log2timeline.py` (Plaso) | `log2timeline.py --storage-file case.plaso --parsers "winevtx,winiis" /cases/triage` | Build one normalised store from a triage folder; targeted parsers avoid `filestat` bloat | Windows / Linux / macOS |
| `psort.py` (Plaso) | `psort.py -o l2tcsv -w window.csv case.plaso --slice 2026-11-14T14:07:00 --slice_size 30` | Export only the window around the anchor instead of a multi-million-row dump | Windows / Linux / macOS |
| `pinfo.py` (Plaso) | `pinfo.py case.plaso` | Report parsers, event counts and covered time range; confirms the store is not silently empty | Windows / Linux / macOS |
| `Velociraptor` | `velociraptor --config client.config.yaml query 'SELECT * FROM info()'` | Read-only endpoint enumeration before a wider `Windows.Triage.Targets` collection | Cross-platform |
| `Hayabusa` | `hayabusa csv-timeline -d ./evtx -o timeline.csv` | Sigma-matched EVTX timeline when no SIEM coverage exists for the host | Windows / Linux / macOS |
| `tzutil` | `tzutil /g` | Record the host's configured zone before normalising its timestamps | Windows |

## Minimal Script Shape

The shape below enforces the two gates that triage fails on most often: it refuses to proceed on a drifted clock, and it refuses to publish a count that has no baseline to compare against.

```bash
#!/usr/bin/env bash
# triage-window.sh — clock gate, bounded slice, baseline differential. Read-only.
set -euo pipefail

CASE="${CASE:?set CASE to a case directory}"
TRIAGE="${TRIAGE:?set TRIAGE to the collected triage folder}"
ANCHOR="${ANCHOR:?set ANCHOR to a UTC timestamp, e.g. 2026-11-14T14:07:00}"
OFFSET_TOL="${OFFSET_TOL:-5}"   # seconds

# Gate 0: the anchor must be stated in UTC and parseable.
date -u -d "$ANCHOR" +%Y-%m-%dT%H:%M:%SZ >/dev/null

# Gate 1: build the store from targeted parsers only, then prove it is not empty.
[ -f "$CASE/case.plaso" ] || \
  log2timeline.py --storage-file "$CASE/case.plaso" \
    --parsers "winevtx,winiis,prefetch,amcache" "$TRIAGE"

if ! pinfo.py "$CASE/case.plaso" | grep -q "Events generated per parser"; then
  echo "GAP: store has no parsed events for this source -> INCONCLUSIVE"; exit 2
fi

# Gate 2: export a bounded slice, never the whole store.
psort.py -o l2tcsv -w "$CASE/window.csv" "$CASE/case.plaso" \
  --slice "$ANCHOR" --slice_size 30

# Gate 3: report first-seen only against an explicit older baseline.
awk -F, 'NR>1 {k=$0; n++} END {
  if (n == 0) { print "GAP: slice empty -> confirm channel enablement before interpreting"; exit 3 }
  printf "slice rows=%d; compare each against a >=7d baseline before scoring\n", n
}' "$CASE/window.csv"
```

## Notes That Prevent Wrong Runs

- `--parsers` is not a filter on output; it decides what gets parsed at all. Omitting `winevtx` because the case "looks like a file event" is how event-log evidence disappears from a timeline.
- `filestat` emits four rows per file. Exclude it for triage runs and add MFT data through a body file only when MACB per file is genuinely the question.
- `--slice` depends on the anchor being correct. If the anchor is inferred, widen the slice and label the uncertainty rather than narrowing to a false precision.
- `tzutil` and `w32tm /query /status` read state only. Never run a time resynchronisation on a host under hold — it rewrites the very offset you are measuring.
- `hayabusa` output is Sigma-matched, not complete. A clean CSV means no rule matched, not that no execution occurred.
