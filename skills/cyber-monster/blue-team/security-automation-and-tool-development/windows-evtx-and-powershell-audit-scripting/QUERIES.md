# Detection Queries and Telemetry Artifacts

> Sub-skill: [`windows-evtx-and-powershell-audit-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Offline EVTX and live PowerShell audit artifacts owned by this slug. Field names follow the rendered event XML (`System`/`EventData`); confirm channel names against the host's enabled logs before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Record count from the parser versus a Get-WinEvent Measure-Object count on the same evtx | High | The parser neither skipped nor invented records beyond the corrupt-record count |
| 2 | 4104 block with `complete: false` and `reason: incomplete-at-eof` | High | The log ended mid-script; the gap is reported rather than hidden |
| 3 | `MessageTotal` of `0`/absent on a 4104 record | Medium | Fragment completeness is unknown and must not be assumed complete |
| 4 | Corrupt-record counter above zero | Medium | The file has damaged chunks; the successful records are still trustworthy |
| 5 | `ScriptBlockId` appearing on more than one `Computer` value | High | Fragments were not merged across hosts by raw GUID |

## Detection Artifacts

```text
[windows-evtx-and-powershell-audit-scripting:rule-spec] Event ID 4104 with ScriptBlockId + MessageNumber/MessageTotal keyed per Computer
[windows-evtx-and-powershell-audit-scripting:filter-fp] an unknown MessageTotal is not evidence of a truncated script
[windows-evtx-and-powershell-audit-scripting:correlate] reconstructed script text joined on ScriptBlockId, ordered by MessageNumber
```

Live collection from PowerShell 5.1, which avoids the service-held file lock:

```powershell
$start = (Get-Date).AddHours(-24)
$events = Get-WinEvent -Path .\evidence\PowerShell-Operational.evtx -FilterXPath "*[System[EventID=4104]]" -MaxEvents 20 -ErrorAction Stop
$events | Select-Object RecordId, TimeCreated, MachineName, ProviderName | ConvertTo-Json -Depth 3
$first = [xml]$events[0].ToXml()
$first.Event.EventData.Data | Select-Object Name, '#text' | ConvertTo-Json -Depth 3
```

Offline parse plus reconciliation (the emitted count must equal parsed records minus corrupt ones):

```powershell
python .\evtx_4104_reassemble.py .\evidence\PowerShell-Operational.evtx |
    Set-Content .\out\ps4104-blocks.jsonl
(Get-Content .\out\ps4104-blocks.jsonl | Measure-Object -Line).Lines
Select-String -Path .\out\ps4104-blocks.jsonl -Pattern '"complete":false' | Measure-Object |
    Select-Object -ExpandProperty Count
```

Independent record count for the reconciliation check:

```powershell
(Get-WinEvent -Path .\evidence\PowerShell-Operational.evtx -FilterXPath "*[System[EventID=4104]]" |
    Measure-Object).Count
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the corrupt-record count alongside every parse; a silently zero count on a large evidence file deserves verification.
- Keep the source file read-only and hash it before parsing, so the evidence hash proves the parse did not mutate it.
