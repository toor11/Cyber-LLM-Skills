# Evidence Queries and Attestation Artifacts

> Sub-skill: [`ransomware-response-containment-and-scoping`](SKILL.md) | Family: **Incident Response**

Queries owned by `ransomware-response-containment-and-scoping`. Each class closes one scope question: what was staged, which accounts mapped data, which hosts received writes they never received before, what re-entry path survives isolation, and which segments are simply unmeasured. Victim-side only.

## Class 1 — Staging and packaging detection

Expected hit: a first-seen archive or compression utility on a server, combined with a write pattern that reads from many paths and writes to few, inside the staging window. The destination of the writes becomes the exfiltration question, not a containment one.

```spl
index=edr sourcetype="edr:process" earliest=-7d@d latest=@h
| eval proc=lower(coalesce(process.name,Image))
| where match(proc,"^(rar|7z|7za|winrar|tar|zip|makecab|compress)$")
| join host type=left
    [ search index=edr sourcetype="edr:process" earliest=-30d@d latest=-7d@d
      | eval proc=lower(coalesce(process.name,Image))
      | where match(proc,"^(rar|7z|7za|winrar|tar|zip|makecab|compress)$")
      | stats count as baseline_uses by host ]
| where isnull(baseline_uses)
| stats min(_time) as first_seen, dc(user.name) as principals, values(process.command_line) as cmds by host, proc
```

False-positive note: build servers, log-rotation scripts and DBA maintenance jobs run archivers constantly and will always be first-seen on a host that has only recently been added to collection. Confirm the host's collection age before scoring.

## Class 2 — Discovery breadth by account

Expected hit: a single account enumerating far more share or directory paths than its own 14-day norm, especially an account that normally touches one or two paths. Breadth, not volume, is the signal.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5145 earliest=-14d@d latest=@h
| eval target=lower(RelativeTargetName)
| eval day_bucket=strftime(_time, "%Y-%m-%d")
| stats dc(target) as distinct_paths, count as accesses by day_bucket, SubjectUserName
| eventstats avg(distinct_paths) as mu, stdev(distinct_paths) as sd by SubjectUserName
| where distinct_paths > mu + (3*sd) AND distinct_paths > 50
| sort - distinct_paths
```

False-positive note: backup service accounts and indexers legitimately read every path every day. Exclude documented service principals by name and by logon type before scoring, or the loudest row will always be the backup account.

## Class 3 — Hosts receiving writes from machine accounts

Expected hit: a computer or service account writing to a share on a host it has never written to before, which is how encryption reaches file servers without a human on the console.

```kql
let knownWritePairs = SecurityEvent
| where TimeGenerated between (ago(15d) .. ago(1d))
| where EventID == 5145
| summarize by Account = SubjectUserName, Target = Computer;
SecurityEvent
| where TimeGenerated between (ago(24h) .. now())
| where EventID == 5145 and AccessMask has "0x2"
| summarize Writes = count(), Paths = dcount(RelativeTargetName) by Account = SubjectUserName, Target = Computer
| join kind=leftanti knownWritePairs on Account, Target
| where Writes > 100
| order by Writes desc
```

False-positive note: a newly joined file server, a new DFS replica or a rebalanced cluster produces legitimate first-write pairs. Correlate with a change record before treating the pair as spread.

## Class 4 — Re-entry paths that isolation does not close

Expected hit: a local administrator added, a remote-management service installed, or a scheduled task created inside the intrusion window on a host you intend to keep powered. Each row is a path the operator can use after you isolate the network.

```powershell
# Read-only enumeration. Run against every host in scope before declaring containment.
$since = (Get-Date).AddDays(-14)
$reentry = [ordered] @{
    Host          = $env:COMPUTERNAME
    NewAdmins     = (Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue |
                     Where-Object { $_.PrincipalSource -eq 'Local' }).Name -join ';'
    RemoteTools   = (Get-Service -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match 'teamviewer|screenconnect|anydesk|rustdesk|atera' }).Name -join ';'
    NewTasks      = (Get-ScheduledTask -ErrorAction SilentlyContinue |
                     Where-Object { $_.Date -and ([datetime]$_.Date) -gt $since }).TaskName -join ';'
}
$reentry | ConvertTo-Json -Compress
```

False-positive note: endpoint-management and remote-support agents are legitimately installed by the IT toolchain and will appear on nearly every host. Compare against the sanctioned tool inventory rather than against the host's own history.

## Class 5 — Coverage attestation per segment

Expected hit: a per-segment count of hosts reporting endpoint telemetry and a per-segment count of hosts present in the asset inventory. A large gap between the two means the segment is unmeasured, not clean.

```kql
let inv = Heartbeat | where TimeGenerated > ago(1d) | summarize by Computer;
DeviceInfo
| where Timestamp > ago(1d)
| summarize Reporting = dcount(DeviceName), Segments = make_set(strcat(OSPlatform, "/", MachineGroup), 20) by bin(Timestamp, 1d)
| extend InventorySeen = toscalar(inv | count)
| project Timestamp, Reporting, InventorySeen, Segments
```

False-positive note: decommissioned assets and long-powered-off laptops remain in inventory for weeks and inflate the gap. Compare against the active-asset list rather than the full inventory, and state which list you used.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the containment timestamp next to every scope query result; a scope list without a boundary cannot be used to declare spread stopped.
- Document every sanctioned service principal, management tool and spooling directory before scoring breadth or first-seen rows.
