# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`endpoint-detection-and-edr-operations`](SKILL.md) | Family: **Detection and Monitoring**

Agent health, live triage, and independent corroboration. Commands are read-only unless explicitly marked as an approved collection action. Verify flags against the installed agent and tool versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Velociraptor client | `velociraptor.exe query "SELECT * FROM info()"` | Report agent version and host identity from the other side of the telemetry path | Windows, Linux, macOS |
| Velociraptor artifact | `velociraptor.exe query "SELECT * FROM Artifact.Windows.System.TaskScheduler()"` | Enumerate scheduled tasks with their XML commands and user context | Windows |
| Velociraptor artifact | `velociraptor.exe query "SELECT * FROM Artifact.Windows.Detection.Amcache()"` | Collect AMCache entries with SHA1 for executed-binary triage | Windows |
| Sysmon config dump | `sysmon64 -c` | Prove which event IDs the endpoint channel actually records, independent of the EDR policy | Windows |
| `Get-WinEvent` | `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50` | Sample the independent channel for the same window the EDR covers | Windows |
| `wevtutil` | `wevtutil epl Microsoft-Windows-Sysmon/Operational triage.evtx` | Export a channel for offline analysis with a preserved artifact | Windows |
| `Get-CimInstance` | `Get-CimInstance Win32_Process` returning `ProcessId`, `ParentProcessId`, `CreationDate`, and `CommandLine` | Live process inventory with parent identifiers and creation times, to compare against the EDR tree | Windows |
| WinPmem via Velociraptor | `winpmem()` VQL function inside a collection artifact | Acquire physical memory for volatile-state triage when the EDR view is insufficient | Windows |

## Minimal Script Shape

The script compares the live process inventory with the EDR's view and flags lineage disagreements, without modifying the host.

```powershell
# lineage-check.ps1 — live inventory versus reported lineage, read-only.
param(
  [Parameter(Mandatory)] [string]$EdrExport   # CSV: DeviceName,ProcessId,ParentProcessId,FileName,Created
)
$ErrorActionPreference = 'Stop'

$live = Get-CimInstance Win32_Process |
  Select-Object ProcessId, ParentProcessId, Name,
                @{n='Created';e={ $_.CreationDate }}

$edr = Import-Csv $EdrExport

# 1. Processes the EDR did not report at all.
$missing = $live | Where-Object { $_.ProcessId -notin $edr.ProcessId }
"live_not_in_edr: $($missing.Count)"

# 2. Lineage disagreements: the EDR's parent differs from the live parent.
$joined = foreach ($p in $live) {
  $e = $edr | Where-Object { $_.ProcessId -eq $p.ProcessId } | Select-Object -First 1
  if ($e -and $e.ParentProcessId -ne $p.ParentProcessId) {
    [pscustomobject]@{
      ProcessId = $p.ProcessId; Name = $p.Name
      LiveParent = $p.ParentProcessId; EdrParent = $e.ParentProcessId
    }
  }
}
$joined | Format-Table -AutoSize

# 3. Impossible lineage: a child created before its reported parent.
foreach ($p in $live) {
  $parent = $live | Where-Object { $_.ProcessId -eq $p.ParentProcessId } | Select-Object -First 1
  if ($parent -and $parent.Created -gt $p.Created) {
    "IMPOSSIBLE_LINEAGE pid=$($p.ProcessId) name=$($p.Name) parent=$($parent.Name)"
  }
}
```

## Notes That Prevent Wrong Runs

- A process identifier is reused; always carry the creation time with it, or a timeline assembled on the identifier alone will attribute another process's actions.
- `ParentProcessId` on a live process can point at an identifier already recycled, so the live parent may be a different process than the original ancestor. Compare creation times.
- Sysmon event 25 is low volume but does not detect every hollowing variant; treat its absence as uninformative rather than as a negative.
- Defender XDR tables ingested only into the Sentinel data lake tier are not visible to analytics rules or the Logs blade, so a query returning nothing may be reading the wrong tier rather than an empty dataset.
- Memory acquisition changes volatile state; record the acquisition time and hash, and perform it before any containment action that would terminate processes.
