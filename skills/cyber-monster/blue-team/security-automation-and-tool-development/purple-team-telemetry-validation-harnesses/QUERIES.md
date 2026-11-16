# Detection Queries and Telemetry Artifacts

> Sub-skill: [`purple-team-telemetry-validation-harnesses`](SKILL.md) | Family: **Security Automation and Tool Development**

Validation and coverage-layer artifacts owned by this slug. All cases run in an isolated lab and every one has a cleanup path.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Correlation id present in the collected event | High | The event observed is the one the case produced |
| 2 | Measured latency from action to event | High | MTTD is measured, not assumed |
| 3 | `fired: false` with `collected: true` | High | Detection gap, distinct from a collection gap |
| 4 | `fields_complete: false` | Medium | The rule matched but the record cannot be triaged |
| 5 | `cleanup_ok: true` on every case | High | The lab returned to baseline and the next run is valid |

## Detection Artifacts

```text
[purple-team-telemetry-validation-harnesses:rule-spec] execute benign action with correlation id, poll bounded, assert collected/fired/fields separately
[purple-team-telemetry-validation-harnesses:filter-fp] rule existence is not coverage; only an observed event proves the path
[purple-team-telemetry-validation-harnesses:correlate] correlation id ties the lab action to one telemetry document
```

Search the SIEM for a case's correlation id after execution (Windows PowerShell 5.1):

```powershell
$id = "pt-powershell_encoded_command-9f1c2a4b7d3e"
$body = @{ query = "SecurityEvent | where CommandLine contains '$id' | take 5" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://siem.example.internal/api/query" -Body $body -ContentType "application/json" |
    Select-Object -ExpandProperty rows
```

Latency measurement, recorded rather than estimated:

```powershell
$start = Get-Date
$deadline = $start.AddMinutes(5)
do {
    $hit = Invoke-RestMethod -Method Post -Uri "https://siem.example.internal/api/query" -Body $body -ContentType "application/json"
    if ($hit.rows.Count -gt 0) { break }
    Start-Sleep -Seconds 15
} while ((Get-Date) -lt $deadline)
if ($hit.rows.Count -gt 0) {
    Write-Output ("latency_seconds={0}" -f [math]::Round(((Get-Date) - $start).TotalSeconds, 1))
} else {
    Write-Output "no telemetry within window: collection or onboarding gap"
}
```

Navigator layer skeleton that must carry `versions.layer: "4.5"` and a valid domain:

```json
{
  "name": "Purple team validation",
  "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "15"},
  "domain": "enterprise-attack",
  "description": "Measured coverage from controlled telemetry validation",
  "techniques": [
    {"techniqueID": "T1059.001", "score": 100, "comment": "collected=true fired=true fields=true"},
    {"techniqueID": "T1547.001", "score": 50, "comment": "collected=true fired=false"}
  ],
  "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100}
}
```

Layer validity check before publishing:

```powershell
$layer = Get-Content .\build\layer.json -Raw | ConvertFrom-Json
Write-Output ("layer_version={0} domain={1} techniques={2}" -f $layer.versions.layer, $layer.domain, $layer.techniques.Count)
if ($layer.versions.layer -ne "4.5") { Write-Output "unsupported layer version"; exit 2 }
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Run every case with cleanup verified before the next case starts; a dirty lab invalidates subsequent measurements.
- Keep the per-case evidence rows beside the published layer; the layer is a summary, not the record.
