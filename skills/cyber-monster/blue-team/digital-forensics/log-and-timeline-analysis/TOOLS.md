# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`log-and-timeline-analysis`](SKILL.md) | Family: **Digital Forensics**

Extraction, filtering and ordering tooling. Never invent undocumented flags — confirm with `<tool> --help` on the installed build, because `psort.py`'s filter syntax and output-module options change between Plaso releases, and `mactime`'s date-range parsing depends on whether `-y` is set. Extraction runs against copies and writes storage files outside the evidence volume.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `log2timeline.py` | `log2timeline.py --storage-file <t.plaso> <image>` | Extract once from an image or directory into a storage file | Cross-platform |
| `pinfo.py` | `pinfo.py <t.plaso>` | Report parsers used, event counts, time range and warnings — the extraction's coverage statement | Cross-platform |
| `psort.py` | `psort.py -q -o dynamic --output_time_zone UTC -w <out.csv> <t.plaso> "<filter>"` | Filter, sort and export a window with timestamp semantics retained | Cross-platform |
| `psteal.py` | `psteal.py --source <image> -o dynamic -w <out.csv>` | One-step extraction and export when a repeatable storage file is not needed | Cross-platform |
| `fls` + `mactime` | `fls -r -m / -o <sector> <img> > body.txt` then `mactime -b body.txt -d -y` | Filesystem-only timeline including deleted entries, rendered in UTC | Cross-platform |
| `journalctl` | `journalctl --directory=<dir> -o json` | Structured journal export with `__SEQNUM` and `__REALTIME_TIMESTAMP` | Linux |

## Minimal Script Shape

The shape below extracts once, records the extraction's own coverage, and produces both the incident window and a comparable baseline — the two artefacts a timeline claim needs in order to be reviewable.

```bash
#!/usr/bin/env bash
# timeline-window.sh — extract once, export a window and its baseline in UTC.
set -euo pipefail

IMG="${1:?usage: timeline-window.sh <image> <case-dir> <start> <end> <baseline-start> <baseline-end>}"
CASE="${2:?}"; START="${3:?}"; END="${4:?}"; B_START="${5:?}"; B_END="${6:?}"
T="$CASE/timeline"; mkdir -p "$T"

if [ ! -f "$T/case.plaso" ]; then
  log2timeline.py --storage-file "$T/case.plaso" "$IMG"
  pinfo.py "$T/case.plaso" > "$T/extraction-report.txt"
fi

FIELDS=datetime,timestamp_desc,source,hostname,user,message

psort.py -q -o dynamic --output_time_zone UTC --fields "$FIELDS" \
  -w "$T/window.csv" "$T/case.plaso" "date > '$START' AND date < '$END'"

psort.py -q -o dynamic --output_time_zone UTC --fields "$FIELDS" \
  -w "$T/baseline.csv" "$T/case.plaso" "date > '$B_START' AND date < '$B_END'"

printf 'window_rows=%s baseline_rows=%s\n' \
  "$(( $(wc -l < "$T/window.csv") - 1 ))" "$(( $(wc -l < "$T/baseline.csv") - 1 ))"
grep -Ei 'warn|error' "$T/extraction-report.txt" | head -5 || echo "no extraction warnings"
```

## Notes That Prevent Wrong Runs

- `--output_time_zone UTC` is mandatory for cross-source work; without it exports render in the analysis host's zone and every comparison with a UTC source shifts by that offset.
- `--fields` replaces the default column set. Always include `timestamp_desc`, or the report cannot distinguish a creation event from a modification event.
- `--slice` takes an anchor in the storage file's own time base and `--slice_size` in minutes. An empty slice is usually a local-versus-UTC mistake at the anchor.
- `pinfo.py` output is evidence: keep it with the case, because it is the only record of which parsers ran and which artifacts produced warnings.
- A bodyfile is not a super timeline. It has no content, its creation times are filesystem-dependent, and `mactime -y` renders UTC while `-z` without `-y` selects the zone used for rendering only. Record which form you produced.
- Plaso storage files are version-coupled to the Plaso that wrote them. Record the version beside the file, or a later analyst cannot reopen it.
