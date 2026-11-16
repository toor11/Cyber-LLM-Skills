# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-evtx-and-powershell-audit-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `Get-Help Get-WinEvent -Full` on the host if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python `evtx` (`from evtx import PyEvtxParser`; `records()` yields `event_record_id`, `timestamp`, `data` as XML) with pure-Python `python-evtx` (`import Evtx.Evtx as evtx`, `record.xml()`) as the portable fallback
- **Live collection:** `Get-WinEvent -FilterHashtable @{LogName=...; Id=...; StartTime=...}`
- **Validation Gate:** `python -m py_compile evtx_4104_reassemble.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `evtx` (PyPI) | `PyEvtxParser("Security.evtx").records()` | Stream records as XML strings with record id and timestamp | Windows/Linux/macOS, Python >= 3.10 |
| `evtx` (PyPI) | `PyEvtxParser(path).records_json()` | Stream records as JSON strings (parse `record["data"]` with `json.loads`) | Same |
| `python-evtx` | `Evtx.Evtx(path)` context manager, `record.xml()` | Dependency-light pure-Python parsing, much slower on large logs | Any Python 3 |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}` | Live channel query without touching the file handle | Windows PowerShell 5.1 |
| `Get-WinEvent` | `Get-WinEvent -Path .\File.evtx -FilterXPath "*[System[EventID=4104]]"` | Offline filtered query for an independent count | Windows PowerShell 5.1 |
| `Get-WinEvent` | `-MaxEvents 100`, `-Oldest` | Bound and order the result set | Windows PowerShell 5.1 |
| PowerShell | `[xml]$evt.ToXml()` then `.Event.EventData.Data` | Extract named `EventData` fields from a returned record | Windows PowerShell 5.1 |

## Minimal Script

```powershell
# Offline reassembly with reconciliation against the engine's own count.
python .\evtx_4104_reassemble.py .\evidence\PowerShell-Operational.evtx |
    Set-Content .\out\ps4104-blocks.jsonl
if ($LASTEXITCODE -ne 0) { Write-Output "parser failed: $LASTEXITCODE"; exit 2 }

$engineCount = (Get-WinEvent -Path .\evidence\PowerShell-Operational.evtx -FilterXPath "*[System[EventID=4104]]" | Measure-Object).Count
$blockCount  = (Get-Content .\out\ps4104-blocks.jsonl | Measure-Object -Line).Lines
$incomplete  = (Select-String -Path .\out\ps4104-blocks.jsonl -Pattern '"complete":false' | Measure-Object).Count
Write-Output "engine=$engineCount blocks=$blockCount incomplete=$incomplete"
if ($engineCount -gt 0 -and $blockCount -eq 0) { exit 1 }
```

Exit-code contract: `0` records reconciled (differences explained by the corrupt-record counter), `1` reconciliation mismatch or no blocks produced from a non-empty log, `2` missing file or parser package.
