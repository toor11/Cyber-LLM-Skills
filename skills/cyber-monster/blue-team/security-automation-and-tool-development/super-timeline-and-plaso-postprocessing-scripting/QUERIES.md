# Detection Queries and Telemetry Artifacts

> Sub-skill: [`super-timeline-and-plaso-postprocessing-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Timeline-reduction artifacts owned by this slug. Every reduction emits a manifest beside its rows; a timeline without one is an unverifiable deletion.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Per-rule dropped count summing to the row delta | High | Nothing was removed outside the declared rules |
| 2 | `seed_hits` count matching the number of seeds | High | The pivot windows contain the events under investigation |
| 3 | `datetime` values all carrying an offset | High | Rows are placed at the correct instant |
| 4 | `timestamp_desc` retained on every row | High | A creation time is not confused with a log event time |
| 5 | Registry-source rows surviving noise suppression | High | Persistence evidence was not filtered out as OS noise |

## Detection Artifacts

```text
[super-timeline-and-plaso-postprocessing-scripting:rule-spec] pivot windows plus rule-based noise suppression with per-rule counts
[super-timeline-and-plaso-postprocessing-scripting:filter-fp] registry writes are never noise; suppress only file-churn and update traffic
[super-timeline-and-plaso-postprocessing-scripting:correlate] seed time + window bounds define the reportable interval
```

Generating the export with the columns a reduction needs (Windows PowerShell 5.1):

```powershell
log2timeline.py --storage-file .\work\timeline.plaso .\evidence\C
psort.py -o l2tcsv -w .\work\timeline.csv .\work\timeline.plaso
Get-Content .\work\timeline.csv -TotalCount 1
```

Confirming the column set before reducing, since a missing column makes every downstream step silently wrong:

```powershell
$header = (Get-Content .\work\timeline.csv -TotalCount 1) -split ','
foreach ($c in @('datetime','timestamp_desc','source','message')) {
    Write-Output "$c=$($header -contains $c)"
}
```

Reducing around two seed events with a reconciled manifest:

```powershell
python .\timeline_slice.py .\work\timeline.csv "2026-11-14T09:12:00Z" "2026-11-14T11:45:30Z" `
    1> .\work\sliced.jsonl 2> .\work\manifest.json
$slice = $LASTEXITCODE
Get-Content .\work\manifest.json
Write-Output "slice_exit=$slice"
```

Verifying the reconciliation arithmetic independently:

```powershell
$manifest = Get-Content .\work\manifest.json -Raw | ConvertFrom-Json
$sum = 0
$manifest.manifest.dropped_by_rule.PSObject.Properties | ForEach-Object { $sum += $_.Value }
$delta = $manifest.manifest.input_rows - $manifest.manifest.output_rows
Write-Output "dropped_sum=$sum row_delta=$delta reconciled=$($sum -eq $delta)"
```

Timesketch import check — the three mandatory fields must be present in the reduced file:

```powershell
python -c "import csv,sys; h=next(csv.reader(open(sys.argv[1],encoding='utf-8'))); print([c for c in ('message','datetime','timestamp_desc') if c not in h])" .\work\sliced.jsonl
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Keep the full export; the reduction must always be reproducible from it.
- Report the reduction manifest with every timeline handed to an investigator.
