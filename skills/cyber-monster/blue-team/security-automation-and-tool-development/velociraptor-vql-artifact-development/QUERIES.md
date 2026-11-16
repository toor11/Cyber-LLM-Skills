# Detection Queries and Telemetry Artifacts

> Sub-skill: [`velociraptor-vql-artifact-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Artifact, verify, and collection artifacts owned by this slug. Confirm plugin availability against the installed client version before deployment; server and client plugin sets differ across releases.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `resources.ops_per_second` / `cpu_limit` present | High | The artifact is rate-bounded per endpoint |
| 2 | `max_rows` reached during a hunt | High | Results are truncated; the collection is partial and must be labelled |
| 3 | `artifacts verify` non-zero exit | High | YAML/VQL defect caught before the artifact reaches a fleet |
| 4 | `parse_evtx` called without a channel or ID filter | Medium | Full-log decode; the dominant cost in endpoint CPU terms |
| 5 | `parameters` entry without a `type` or `default` | Medium | Unvalidated input reaching a path or regex |

## Detection Artifacts

```text
[velociraptor-vql-artifact-development:rule-spec] typed parameters + resources block + bounded LIMIT on every artifact
[velociraptor-vql-artifact-development:filter-fp] max_rows truncation is partial data, not evidence of a clean host
[velociraptor-vql-artifact-development:correlate] Computer + EventRecordID + Channel keys one event across collections
```

Verify gate, then a single-endpoint dry collection (Windows PowerShell 5.1):

```powershell
velociraptor.exe artifacts verify .\artifacts\Custom.Windows.EventLogs.PowerShellScriptBlock.yaml
$verify = $LASTEXITCODE
if ($verify -ne 0) { Write-Output "artifact failed verification: $verify"; exit 2 }

velociraptor.exe artifacts collect Custom.Windows.EventLogs.PowerShellScriptBlock `
    --args EvtxGlob="C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" `
    --format json | Set-Content .\build\ps4104.json
```

Enumerating available plugins and their parameters before writing a query:

```powershell
velociraptor.exe query "SELECT * FROM info()" --format json
velociraptor.exe query "SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx') LIMIT 2"
```

Artifact naming and discovery:

```powershell
velociraptor.exe artifacts list | Select-String -Pattern 'Custom\.Windows\.'
Get-ChildItem .\artifacts\Custom.*.yaml | ForEach-Object { $_.BaseName }
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Run any new `parse_evtx`/`parse_mft`/`yara` artifact against one representative endpoint of each class before a fleet hunt.
- Record the artifact version in the hunt description; results without a version are not reproducible.
