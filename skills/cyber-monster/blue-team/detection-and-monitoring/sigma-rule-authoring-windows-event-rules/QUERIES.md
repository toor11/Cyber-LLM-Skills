# Detection Queries and Telemetry Artifacts

> Sub-skill: [`sigma-rule-authoring-windows-event-rules`](SKILL.md) | Family: **Detection and Monitoring**

Windows rule precondition checks owned by `sigma-rule-authoring-windows-event-rules`. Each class proves one thing the rule assumes: the event can exist, the config emits it, the field is in that template, and the rule fires on the right lineage. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Audit policy for the event ID

Expected hit: the subcategory behind the event ID is enabled for success, failure, or both. A disabled subcategory means the rule can never match regardless of its logic.

```powershell
# Which audit subcategories are enabled, and at what level.
auditpol /get /category:* | Select-String -Pattern 'Success|Failure' |
  Where-Object { $_ -match 'Process Creation|Logon|File System|Registry|Audit Policy' }
```

```powershell
# Confirm the specific subcategory behind 4688 in Group Policy terms.
auditpol /get /subcategory:"Process Creation"
```

False-positive note: `auditpol` reflects the local policy; a domain GPO applied at the site level can override it without appearing here, so confirm on a host in the actual OU.

## Class 2 — Sysmon configuration coverage

Expected hit: the event type the rule selects is present in the running config, and the version supports it. 27 and 28 are blocking-only and never appear as filterable events.

```powershell
# Dump the running configuration and list the enabled event types.
sysmon -c
```

```powershell
# Schema and driver state, to confirm the installed version supports the ID you need.
Get-CimInstance -Namespace root\Microsoft\Windows\Sysmon -ClassName Win32_DeviceGuard |
  Select-Object -Property *
(Get-Item "$env:SystemRoot\System32\drivers\SysmonDrv.sys").VersionInfo.FileVersion
```

False-positive note: `sysmon -c` prints the config as loaded, not as authored; a config on disk that differs from the loaded one is a common reason a rule appears covered and is not.

## Class 3 — Event template fields for one ID

Expected hit: the field the rule selects on appears in that event ID's own `EventData`. Adjacent IDs in the same channel do not share templates.

```powershell
# Show the EventData names an event ID actually carries.
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 1 |
  ForEach-Object { $_.ToXml() } |
  Select-String -Pattern '<Data Name="([^"]+)"' -AllMatches |
  ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
```

False-positive note: an event written before a Windows update may use an older template; sample from several hosts before concluding a field name is wrong.

## Class 4 — PowerShell logging mode in force

Expected hit: 4104 present for hosts running scripts when the rule reads script content; 4103 present when the rule reads module pipeline events. Neither substitutes for the other.

```powershell
# Script block logging state.
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
# Module logging state.
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
```

```powershell
# Empirical check: does the channel actually carry 4104 for this host today?
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5 |
  Select-Object TimeCreated, Id, @{n='Len';e={$_.Properties[2].Value.Length}}
```

False-positive note: a host that ran no PowerShell legitimately shows zero 4104 events; verify the policy state before concluding logging is broken.

## Class 5 — Conversion and lineage baseline

Expected hit: the converted rule fires on a positive replay and its benign hits concentrate on known management parents rather than user-launched binaries.

```powershell
sigma convert -t splunk -p splunk_windows .\rules\service_user_writable.yml
```

```spl
index=wineventlog sourcetype="WinEventLog:System" EventCode=7045 earliest=-7d@d
| eval dir = case(match(ImagePath,"(?i)\\\\Users\\\\"), "user",
                  match(ImagePath,"(?i)\\\\ProgramData\\\\"), "programdata",
                  match(ImagePath,"(?i)\\\\Temp\\\\"), "temp", true(), "other")
| stats count BY dir, ServiceName
| where dir in ("programdata", "temp")
```

False-positive note: vendor updaters stage under ProgramData by design; the finding is a service installed from a user-writable path by a non-installer parent, not the path alone.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the audit subcategory state, the Sysmon config version and the PowerShell logging mode with every deployed Windows rule.
