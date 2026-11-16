# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`detection-coverage-and-mitre-gap-analyzer-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11 with `pyyaml` for Sigma rule YAML (`logsource`, `tags` with `attack.tNNNN[.NNN]`), a normalized datasource inventory, and an ATT&CK technique list for the version in use
- **Validation Gate:** `python -m py_compile coverage_gap.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pyyaml` | `yaml.safe_load(path.read_text())` | Parse rule documents | Python 3.11+ |
| `pySigma` | `SigmaCollection.load_ruleset([...], collect_errors=True)` | Object-model parse with per-rule errors | Python |
| `pySigma` | `rule.tags`, `rule.logsource` | Authoritative logsource and ATT&CK tag access | Python |
| `pathlib` | `Path.rglob("*.yml")` | Enumerate a rule repository | Python 3.11+ |
| `collections` | `defaultdict` keyed by technique | Build the per-technique evidence matrix | Python 3.11+ |
| ATT&CK data | current enterprise/mobile/ics technique list | Validate technique IDs and parent relationships | JSON/STIX |

## Minimal Script

```powershell
python -m py_compile .\coverage_gap.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\coverage_gap.py .\rules .\datasources.yaml .\profile.json | Set-Content .\build\coverage.json
$analysis = $LASTEXITCODE
if ($analysis -eq 2) { Write-Output "unreadable rules or inventory"; exit 2 }

$report = Get-Content .\build\coverage.json -Raw | ConvertFrom-Json
$covered = ($report.matrix | Where-Object { $_.verdict -eq 'covered' }).Count
$total = $report.matrix.Count
Write-Output "covered=$covered total=$total dead_rules=$($report.dead_rules.Count)"
exit $analysis
```

Exit-code contract: `0` matrix produced with full coverage, `1` gaps found, `2` unreadable repository or missing inventory.
