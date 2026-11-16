# Detection Queries and Telemetry Artifacts

> Sub-skill: [`detection-coverage-and-mitre-gap-analyzer-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Coverage-matrix artifacts owned by this slug. Every cell names the rules and log sources that produced it.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Rule `logsource` joined to an inventory key | High | The rule's data dependency is mapped to something the estate reports |
| 2 | `disabled` as a distinct state from `not_collected` | High | Operational gaps are separated from content gaps |
| 3 | Technique verdict `content_gap` when all rules are dead | High | Dead content does not inflate coverage |
| 4 | Parent rollup emitted separately from child rows | High | Sub-technique coverage is not silently generalized |
| 5 | Evidence arrays on each matrix row | High | A coverage percentage is traceable to specific rules |

## Detection Artifacts

```text
[detection-coverage-and-mitre-gap-analyzer-scripting:rule-spec] coverage requires a rule AND an enabled collected log source
[detection-coverage-and-mitre-gap-analyzer-scripting:filter-fp] disabled-at-sensor is an operational gap, not a content gap
[detection-coverage-and-mitre-gap-analyzer-scripting:correlate] technique -> rules -> logsources -> inventory state
```

Inventory shape the analyzer expects — the `enabled` flag is what separates operational from content gaps:

```yaml
sources:
  - product: windows
    category: process_creation
    enabled: true
  - product: windows
    service: security
    enabled: false
  - product: linux
    category: process_creation
    enabled: true
```

Run the analyzer and read the verdict distribution (Windows PowerShell 5.1):

```powershell
python .\coverage_gap.py .\rules .\datasources.yaml .\profile.json | Set-Content .\build\coverage.json
$analysis = $LASTEXITCODE
$report = Get-Content .\build\coverage.json -Raw | ConvertFrom-Json
$report.matrix | Group-Object verdict | Select-Object Name, Count
Write-Output "analyzer_exit=$analysis"
```

List the dead rules that inflate a naive count:

```powershell
$report = Get-Content .\build\coverage.json -Raw | ConvertFrom-Json
$report.dead_rules | Group-Object reason | ForEach-Object {
    Write-Output ("{0}: {1}" -f $_.Name, $_.Count)
}
$report.dead_rules | Select-Object -First 10 | Format-Table -AutoSize
```

Confirm a specific technique's evidence before publishing a coverage claim:

```powershell
($report.matrix | Where-Object { $_.technique -eq 'T1059.001' }) | ConvertTo-Json -Depth 4
```

Rule-tag extraction check, so technique attribution comes from metadata rather than inference:

```powershell
Select-String -Path .\rules\**\*.yml -Pattern '^\s*-\s*attack\.t\d{4}' |
    Select-Object -First 10 | ForEach-Object { $_.Line.Trim() }
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Refresh the datasource inventory whenever sensor configuration changes; a stale inventory produces a confidently wrong matrix.
- Publish the per-technique evidence with any coverage percentage so a challenged figure can be traced.
- Pair the matrix with measured validation before reporting coverage to leadership.
