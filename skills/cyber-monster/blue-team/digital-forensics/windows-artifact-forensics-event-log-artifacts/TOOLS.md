# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-artifact-forensics-event-log-artifacts`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for reading, exporting and parsing Windows event logs. Confirm options with `<tool> --help` on the installed build; `EvtxECmd` and `evtx_dump` have different output shapes and neither is a drop-in for the other.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `wevtutil` | `wevtutil epl Security C:\case\Security.evtx /ow:true` | Export a whole channel to a file before any query touches the live log | Windows |
| `EvtxECmd` | `EvtxECmd.exe -d C:\case\logs --csv C:\case\out --csvf events.csv` | Parse a directory of EVTX into a single CSV with per-record metadata | Windows |
| `evtx_dump` | `evtx_dump -o json Microsoft-Windows-PowerShell%4Operational.evtx` | JSON lines from EVTX on non-Windows hosts; useful for scripted extraction | Linux, macOS |
| `python-evtx` | `python -c "from Evtx.Evtx import Evtx; [print(r.xml()) for r in Evtx('Security.evtx').records()]"` | Programmatic record-level access including chunk headers | Cross-platform |
| `Chainsaw` | `chainsaw hunt C:\case\logs -s sigma/ --mapping mappings/sigma-event-logs-all.yml` | Bulk Sigma matching across a directory of EVTX | Cross-platform |
| `Hayabusa` | `hayabusa csv-timeline -d C:\case\logs -o timeline.csv -w` and `auditpol /get /category:"Detailed Tracking"` | Fast timeline generation with built-in rules, plus the audit state that decides whether an absence means anything | Windows, Linux |

## Minimal Script Shape

The shape below gates on channel presence and audit state before extracting anything, then reassembles script blocks completely and refuses to quote partial ones. Read-only against the exported files.

```powershell
# evtx-scope.ps1 — inventory, policy gate, complete script-block extraction.
param([string]$LogDir = "C:\case\logs", [string]$OutDir = "C:\case\derived")
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 0. Inventory: a channel that is not present cannot answer anything.
Get-ChildItem $LogDir -Filter *.evtx | ForEach-Object {
    [pscustomobject]@{ File = $_.Name; Bytes = $_.Length
        Sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
} | Export-Csv "$OutDir\inventory.csv" -NoTypeInformation

# 1. Audit policy gate: refuse to interpret an absent 4688.
$pol = auditpol /get /subcategory:"Process Creation" | Out-String
if ($pol -notmatch "Success") {
    "GAP: Process Creation audit disabled -> 4688 absence is uninterpretable" |
        Tee-Object "$OutDir\gaps.txt"
}

# 2. Script blocks: only quote a block whose parts cover its declared total.
$ps = Join-Path $LogDir "Microsoft-Windows-PowerShell%4Operational.evtx"
if (Test-Path $ps) {
    Get-WinEvent -Path $ps -FilterXPath "*[System[EventID=4104]]" -ErrorAction SilentlyContinue |
      ForEach-Object {
          $x = [xml]$_.ToXml(); $d = @{}
          $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
          [pscustomobject]@{ Id = $d['ScriptBlockId']; N = [int]$d['MessageNumber']
                             Total = [int]$d['MessageTotal']; Text = $d['ScriptBlockText'] }
      } | Group-Object Id | ForEach-Object {
          $declared = ($_.Group | Select-Object -First 1).Total
          [pscustomobject]@{
              ScriptBlockId = $_.Name; Parts = $_.Count; Declared = $declared
              Complete = ($_.Count -eq $declared)
              Text = ($_.Group | Sort-Object N | ForEach-Object Text) -join ''
          }
      } | Export-Csv "$OutDir\scriptblocks.csv" -NoTypeInformation
}
```

## Notes That Prevent Wrong Runs

- `wevtutil epl` is the only reliable way to preserve a live channel; querying with `Get-WinEvent` and piping to CSV loses record IDs and provider metadata that later analysis needs.
- `evtx_dump` emits one JSON object per record, not an array; feed it line-by-line rather than attempting to load it as a single document.
- `Chainsaw` and `Hayabusa` apply their own rule sets. A zero-hit run means their rules did not match, not that the events are absent — always keep the raw parse beside the rule output.
- Sysmon events 27 and 28 are blocking-only and are never written to the log. An absent 27 never means "no file-blocking occurred"; it means the rule was not in blocking mode.
