# Evidence Extraction Artifacts and Queries

> Sub-skill: [`windows-artifact-forensics-event-log-artifacts`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `windows-artifact-forensics-event-log-artifacts`. Each class names the file or channel being read, the parser invocation that extracts it, and the filter that turns records into a finding. Offline parsing uses `EvtxECmd` or `evtx_dump`; live hosts use `Get-WinEvent` only after the channels have been exported.

## Class 1 — Channel inventory and integrity

Expected hit: one row per channel with record count, first and last record, and the file hash. A channel with records that stop days before acquisition is the first anomaly to explain.

```powershell
Get-WinEvent -ListLog Security, System, Application, "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-PowerShell/Operational" |
  Select-Object LogName, RecordCount, FileSize, IsEnabled, LogMode | Format-Table -AutoSize
Get-FileHash C:\Windows\System32\winevt\Logs\Security.evtx -Algorithm SHA256
```

False-positive note: `RecordCount` of zero on an enabled channel is normal immediately after rotation, and `IsEnabled` false is a configuration state rather than evidence of tampering. Record both values before drawing any conclusion from a sparse channel.

## Class 2 — Audit policy state (the denominator)

Expected hit: `Process Creation` and `Logon` subcategories showing Success auditing for the incident window. Without that, every 4688 or 4624 absence is uninterpretable.

```powershell
auditpol /get /category:"Detailed Tracking","Logon/Logoff" /r
```

False-positive note: advanced audit policy can be set by GPO at a level that overrides local settings, so a local `auditpol` reading may not reflect what the domain enforces. Check the applied GPO or the `Microsoft-Windows-Security-Auditing` 4719 events in the same window.

## Class 3 — Authentication events by principal and source

Expected hit: per-principal counts of 4624/4625/4648 for the probe window beside the same counts for a quiet baseline window, with the failed-then-successful transition visible for any burst.

```powershell
$p = @{LogName='Security'; Id=4624,4625; StartTime=$start; EndTime=$end}
Get-WinEvent -FilterHashtable $p |
  ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data|%{$d[$_.Name]=$_.'#text'}
    [pscustomobject]@{Id=$_.Id; User=$d['TargetUserName']; Type=$d['LogonType']; Src=$d['IpAddress']; LId=$d['TargetLogonId']} } |
  Group-Object User, Type | Sort-Object Count -Descending | Select-Object -First 20
```

False-positive note: logon type 3 from a machine account is the ordinary shape of service authentication and SMB scanning. Compare against that account's own baseline before treating volume as anomalous, and join on `TargetLogonId` to link 4624 with a following 4672.

## Class 4 — Process creation with parent context

Expected hit: 4688 rows with `CreatorProcessName` and `NewProcessName` both populated. A child in a user-writable directory under a signed system parent is the pairing that matters.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5000 |
  ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data|%{$d[$_.Name]=$_.'#text'}
    [pscustomobject]@{Time=$_.TimeCreated; Parent=$d['CreatorProcessName']; Child=$d['NewProcessName']; Cmd=$d['CommandLine']} } |
  Where-Object { $_.Child -and $_.Child -notmatch '^C:\\Windows\\' } | Format-Table -Wrap
```

False-positive note: `CreatorProcessName` can be empty on hosts where the calling process exited before the audit record was written. An empty parent is a missing value, not an absent parent — pivot to Sysmon 1 for the same time and image before concluding orphaned execution.

## Class 5 — Script block reassembly

Expected hit: every 4104 for a `ScriptBlockId` present as a complete numbered set, with the reassembled text quoting the full block rather than one fragment.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 3000 |
  ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data|%{$d[$_.Name]=$_.'#text'}
    [pscustomobject]@{Id=$d['ScriptBlockId']; N=[int]$d['MessageNumber']; T=$d['MessageTotal']; Text=$d['ScriptBlockText']} } |
  Group-Object Id | ForEach-Object {
    [pscustomobject]@{ Id=$_.Name; Parts=$_.Count; Declared=$_.Group[0].T
      Text=($_.Group | Sort-Object N | ForEach-Object Text) -join '' } } |
  Where-Object { $_.Parts -eq [int]$_.Declared } | Select-Object Id, Parts, Text
```

False-positive note: a block whose captured part count is below its declared `MessageTotal` is incomplete, and quoting it produces truncated text that looks like deliberate obfuscation. Report the missing fragment count instead of guessing at the missing content.

## Class 6 — Channel tampering and rotation

Expected hit: 1102 for a clear, or a record-ID discontinuity with an accompanying archived file and a channel creation time that explains it.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,4719} -MaxEvents 200 |
  Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Substring(0,[Math]::Min(180,$_.Message.Length))}}
Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 1 | Select-Object RecordId, TimeCreated
```

False-positive note: reaching the configured maximum log size causes rotation and a record-ID reset with no 1102. Compare the file's creation time and the presence of `.evtx` archives in the same directory before describing the discontinuity as deliberate clearing.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the audit subcategory state and the Sysmon configuration version beside every event-derived finding; both change what an absence means.
