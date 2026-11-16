# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sigma-rule-authoring-windows-event-rules`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for reading Windows audit state, Sysmon configuration and event templates, then converting the rule. Never invent cmdlet parameters or event IDs — check `Get-Help <cmdlet> -Parameter *` and read a captured event before assuming a field name.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `auditpol` | `auditpol /get /subcategory:"Process Creation"` | Read the audit state behind an event ID so a silent rule is attributed correctly | Windows |
| `sysmon` | `sysmon -c` (dump running config), `sysmon -c <file>` (apply a config) | Confirm which event types the host actually emits before authoring against them | Windows |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 5` | Read real events from the exact channel and ID the rule targets | Windows |
| `Get-WinEvent` (template) | `(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 1).ToXml()` | Extract the `EventData` field names that ID actually carries | Windows |
| `sigma convert` | `sigma convert -t splunk -p splunk_windows rules/rule.yml` | Produce backend query text for review before deployment | Cross-platform |
| `EvtxECmd` | `EvtxECmd.exe -f Microsoft-Windows-Sysmon-Operational.evtx --json .` | Parse a captured EVTX offline to inspect templates without touching production hosts | Windows |

## Minimal Script Shape

The shape below is the minimum defensible Windows rule gate: prove the audit state, prove the config, then read the template fields and convert.

```powershell
# windows-sigma-gate.ps1 — audit gate, config gate, template gate, conversion gate.
param(
  [string]$Channel = 'System',
  [int]$EventId = 7045,
  [string]$Rule = '.\rules\service_user_writable.yml',
  [string]$Subcategory = 'Process Creation'
)

# 0. Audit gate: the event can only exist if its subcategory is enabled.
$audit = auditpol /get /subcategory:"$Subcategory" | Out-String
if ($audit -notmatch 'Success|Failure') {
  Write-Output "GAP: audit subcategory '$Subcategory' not enabled -> INCONCLUSIVE (Telemetry Gap)"
  exit 2
}

# 1. Sysmon config gate: only relevant for the Sysmon channel.
if ($Channel -like '*Sysmon*') {
  $cfg = sysmon -c | Out-String
  if ($cfg -notmatch "EventFiltering|$EventId") {
    Write-Output "GAP: Sysmon config does not emit event $EventId"
    exit 3
  }
}

# 2. Template gate: list the fields the event ID actually carries.
$evt = Get-WinEvent -FilterHashtable @{LogName=$Channel; Id=$EventId} -MaxEvents 1
if (-not $evt) {
  Write-Output "GAP: no $EventId events in $Channel -> rule input unproven"
  exit 4
}
$xml = $evt.ToXml()
[regex]::Matches($xml, '<Data Name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } |
  Sort-Object -Unique

# 3. Conversion gate: the generated query must reference the channel.
$converted = sigma convert -t splunk -p splunk_windows $Rule
$converted
if ($converted -notmatch 'EventCode|source') {
  Write-Output "GAP: converted query does not target a real channel"
  exit 5
}
```

## Notes That Prevent Wrong Runs

- `sysmon -c` prints the loaded configuration; a config file on disk that differs from it is the usual reason a rule looks covered and never fires.
- `Get-WinEvent -FilterHashtable` silently returns nothing when the channel is disabled rather than erroring, which is indistinguishable from no activity.
- `auditpol` shows local policy; a domain GPO can override it, so confirm on a host in the production OU.
- Sysmon 27 and 28 are blocking-only entries for the driver's own file and registry block lists and are not emitted as filterable events; do not write rules against them.
