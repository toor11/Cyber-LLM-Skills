# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`super-timeline-and-plaso-postprocessing-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `psort.py -h` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Plaso (`log2timeline.py`, `psort.py`) export rows with `datetime`, `timestamp_desc`, `source`, `source_long`, `message`, `parser`; Timesketch import requiring `message`, `datetime`, `timestamp_desc`
- **Validation Gate:** `python -m py_compile timeline_slice.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `log2timeline.py` | `log2timeline.py --storage-file timeline.plaso <evidence>` | Build a Plaso storage file from evidence | Cross-platform |
| `psort.py` | `psort.py -o l2tcsv -w timeline.csv timeline.plaso` | Export a filtered timeline as CSV | Cross-platform |
| `psort.py` | `psort.py -o json_line -w timeline.jsonl timeline.plaso` | JSONL export for streaming consumers | Cross-platform |
| `psort.py` | `--additional-fields data_type` | Include `data_type` beyond the default columns | Cross-platform |
| `timesketch_importer` | `timesketch_importer --sketch_id <id> --timeline_name <name> timeline.csv` | Import a timeline into Timesketch | Cross-platform |
| Python `csv` | `csv.DictReader` over the export | Streaming row access without loading everything | Python 3.11+ |
| Python `datetime` | `datetime.fromisoformat(text.replace("Z", "+00:00"))` | Parse an offset-bearing timeline timestamp | Python 3.11+ |

## Minimal Script

```powershell
python -m py_compile .\timeline_slice.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\timeline_slice.py .\work\timeline.csv "2026-11-14T09:12:00Z" `
    1> .\work\sliced.jsonl 2> .\work\manifest.json
$slice = $LASTEXITCODE

$kept = (Get-Content .\work\sliced.jsonl | Measure-Object -Line).Lines
$manifest = Get-Content .\work\manifest.json -Raw
Write-Output "kept=$kept exit=$slice"
Write-Output $manifest
exit $slice
```

Exit-code contract: `0` reduction reconciled with all seeds found, `1` unreconciled counts or an unparseable row, `2` missing required column or unreadable export.
