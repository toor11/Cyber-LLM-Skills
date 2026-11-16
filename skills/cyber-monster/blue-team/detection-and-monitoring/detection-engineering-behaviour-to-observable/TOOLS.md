# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`detection-engineering-behaviour-to-observable`](SKILL.md) | Family: **Detection and Monitoring**

Introspection tools that answer "does this sensor emit this action, with which fields, on this build". All are read-only. Verify flags against the installed version; Sysmon and Velociraptor both change parameter surfaces between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Sysmon config dump | `sysmon64 -c` | Print the effective configuration so you can see which event IDs the include rules cover | Windows |
| Sysmon schema reference | `sysmon64 -?` plus the vendor event table for schema 4.90 (event IDs 1-26 and 29) | Confirm the event exists and which fields it carries before authoring | Windows |
| `wevtutil` | `wevtutil gl Microsoft-Windows-Sysmon/Operational` | Check the channel is enabled and read its retention and maximum size | Windows |
| `Get-WinEvent` | `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20` then pipe to `ForEach-Object { $_.Properties }` | Sample real events and list the populated properties for this build | Windows |
| Velociraptor VQL | `SELECT EventID, count() AS n FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4AOperational.evtx") GROUP BY EventID` | Inventory emitted event IDs on a host without waiting for SIEM ingestion | Windows, Linux, macOS |
| Velociraptor VQL | `SELECT * FROM watch_etw(guid="{...}") LIMIT 5` | Sample an ETW provider live when a vendor event omits the argument values you need | Windows |
| `auditctl` | `auditctl -l` | List the loaded audit rules, since a syscall observable only exists if a rule selects it | Linux |
| `bpftrace` | `bpftrace -l 'tracepoint:syscalls:sys_enter_*'` | Enumerate available tracepoints when deciding whether an eBPF probe can carry the behaviour | Linux |

## Minimal Script Shape

The script samples the observable on the target build and refuses to report a field as available unless it is populated in the sample.

```powershell
# observable-probe.ps1 — sample one event shape and report which fields survive.
param(
  [Parameter(Mandatory)] [string]$LogName = 'Microsoft-Windows-Sysmon/Operational',
  [Parameter(Mandatory)] [int]$EventId = 10,
  [int]$SampleSize = 50
)
$ErrorActionPreference = 'Stop'

# 1. Is the channel enabled at all?
$channel = wevtutil gl $LogName 2>&1 | Out-String
if ($channel -match 'enabled: false') {
  throw "INCONCLUSIVE (Channel Disabled): $LogName"
}

# 2. Sample events of the target identifier.
$events = Get-WinEvent -LogName $LogName -MaxEvents 500 |
  Where-Object { $_.Id -eq $EventId } |
  Select-Object -First $SampleSize

if (-not $events) {
  throw "INCONCLUSIVE (No Sample): EventID $EventId not emitted in the last 500 records"
}

# 3. Report field population across the sample.
$fieldStats = @{}
foreach ($e in $events) {
  $xml = [xml]$e.ToXml()
  foreach ($d in $xml.Event.EventData.Data) {
    if (-not $fieldStats.ContainsKey($d.Name)) { $fieldStats[$d.Name] = 0 }
    if ($d.'#text') { $fieldStats[$d.Name]++ }
  }
}
$fieldStats.GetEnumerator() |
  Sort-Object Value -Descending |
  ForEach-Object { '{0,-24} populated {1}/{2}' -f $_.Key, $_.Value, $events.Count }
```

## Notes That Prevent Wrong Runs

- `sysmon64 -c` prints the running config; a config file on disk may differ from what the service loaded. Always read the effective config.
- Event 29 (FileExecutableDetected) is the non-blocking counterpart to 27; it carries `Image`, `TargetFilename`, and `Hashes` but not the writing process's command line. Treat the missing command line as a documented loss rather than a mapping defect.
- Sysmon events 27 and 28 are blocking-only and not filterable, so they cannot serve as detection observables.
- `Get-WinEvent` reads a channel, not the forwarder's copy; an event visible here may still be dropped by the forwarder's filter, so confirm at the index before concluding the pipeline carries it.
- On Linux, `auditctl -l` is authoritative for whether a syscall can appear; an eBPF probe can cover a syscall with no audit rule, but its fields are your program's fields, not auditd's.
