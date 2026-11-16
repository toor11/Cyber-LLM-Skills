# Evidence Queries and Attestation Artifacts

> Sub-skill: [`ransomware-response-recovery-and-restore`](SKILL.md) | Family: **Incident Response**

Queries owned by `ransomware-response-recovery-and-restore`. Each class closes one restore-readiness question: is the point old enough, was the target reachable to the operator, is it locked, did restore actually succeed, and did the vector stay closed. Victim-side only.

## Class 1 — Restore-point provenance against the earliest pre-impact artifact

Expected hit: at least one point whose timestamp precedes the earliest pre-impact artifact, with the gap stated in hours. A point that is newer than the implant is a point that restores the implant.

```powershell
# Read-only catalogue inspection. Emits a table; changes nothing.
$firstImplant = Get-Date "2026-11-09T18:20:00Z"
Get-VBRBackup | ForEach-Object {
    $job = $_
    $job.GetAllStorages() | ForEach-Object {
        $pointRecord = [ordered] @{
            Job          = $job.JobName
            PointUtc     = $_.CreationTime.ToUniversalTime()
            AgeBeforeHit = [math]::Round(($firstImplant - $_.CreationTime.ToUniversalTime()).TotalHours, 1)
            UsableForData = $_.CreationTime.ToUniversalTime() -lt $firstImplant
        }
    }
} | Sort-Object PointUtc -Descending | Select-Object -First 15 | Format-Table -AutoSize
```

False-positive note: an incremental point whose parent chain crosses the implant is not safe even when its own timestamp is old, because a restore replays the chain. Inspect the full parent chain, not just the leaf timestamp.

## Class 2 — Immutability and separation attestation

Expected hit: the target reports a configured lock interval and a mount or share path that is not reachable from the affected identity's network position. A target described as immutable in a runbook but configured with no lock interval is a documentation gap with incident consequences.

```kql
// Storage-side view: who wrote to the backup container, and could they delete?
StorageBlobLogs
| where TimeGenerated between (ago(45d) .. now())
| where AccountName startswith "bkprepo"
| where OperationName in ("DeleteBlob","DeleteContainer","SetBlobTier","PutBlob","PutBlock")
| summarize Ops = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by OperationName, CallerIpAddress, Identity = tostring(parse_json(Authentication).identity)
| order by Ops desc
```

False-positive note: the backup service's own automation deletes expired points by design. Establish the sanctioned service identity and its expected deletion cadence first, or every legitimate expiry looks like sabotage.

## Class 3 — Vector-closure test

Expected hit: a post-fix authentication attempt through the original vector that fails with a reason consistent with the remediation — account disabled, credential rejected, path removed, MFA satisfied only by a new factor. Success, or failure for an unrelated reason such as network timeout, does not prove closure.

```kql
let vector = "vpn-gateway-01";
let fixAt = datetime(2026-11-15T09:00:00Z);
let edge = CommonSecurityLog
    | where TimeGenerated > fixAt
    | where DeviceName == vector and DestinationPort in (443,10443)
    | project T=TimeGenerated, Plane="edge", Outcome=DeviceAction, Src=SourceIP, Actor=SourceUserName;
let idp = SigninLogs
    | where TimeGenerated > fixAt and AppDisplayName contains "VPN"
    | project T=TimeGenerated, Plane="idp", Outcome=tostring(ResultType), Src=IPAddress, Actor=UserPrincipalName;
union edge, idp
| where Outcome in ("deny","failure","50126","50074","53003")
| order by T asc
```

False-positive note: users mistyping passwords generate deny events continuously. Closure requires the specific principal and source from the intrusion, or a documented configuration change confirmed by a configuration-management diff — not a general increase in denials.

## Class 4 — Post-restore observation: did the compromise survive?

Expected hit: a restored host whose first-seen set after restore is empty — no new outbound destination, no new service, no new scheduled task, no new local administrator. Any first-seen value that matches a known intrusion indicator means restore failed.

```spl
index=edr earliest=-4h@h latest=@h
| eval host=coalesce(host.name,ComputerName)
| eval obj=case(sourcetype=="edr:process", coalesce(process.path,NewProcessName),
                sourcetype=="edr:network", dest_ip,
                sourcetype=="edr:service", service_name,
                true(), null())
| join host obj type=left
    [ search index=edr earliest=-30d@d latest=-1d@d
      | eval host=coalesce(host.name,ComputerName)
      | eval obj=case(sourcetype=="edr:process", coalesce(process.path,NewProcessName),
                      sourcetype=="edr:network", dest_ip,
                      sourcetype=="edr:service", service_name,
                      true(), null())
      | stats count as prior by host obj ]
| where isnull(prior)
| stats min(_time) as first_seen, values(sourcetype) as planes by host, obj
| sort by first_seen asc
```

False-positive note: a freshly restored host legitimately produces a large first-seen set during its first patch cycle and first user logons. Sequence the observation window from the end of the patch cycle and user acceptance testing, and state the start explicitly.

## Class 5 — Restore fidelity: did the data actually come back intact?

Expected hit: a per-volume or per-application comparison of file counts and a sample hash set between the restore source and the restored target, plus an application-level consistency check. Restore commands report success long before the data is verified.

```powershell
# Read-only post-restore verification: counts and a deterministic sample, no writes to source.
$source = "\\bkprepo\restore\2026-11-08\D"
$target = "D:\"
$sample = Get-ChildItem $source -Recurse -File -ErrorAction SilentlyContinue |
    Get-Random -Count 200

$fidelityCheck = [ordered] @{
    RestoredFrom = $source
    SourceFiles = (Get-ChildItem $source -Recurse -File -ErrorAction SilentlyContinue).Count
    TargetFiles = (Get-ChildItem $target -Recurse -File -ErrorAction SilentlyContinue).Count
    SampleHash  = ($sample | ForEach-Object {
        Get-FileHash $_.FullName -Algorithm SHA256
    } | Measure-Object).Count
} | Format-List

$sample | ForEach-Object {
    $mirror = Join-Path $target $_.FullName.Substring($source.Length).TrimStart('\')
    if (-not (Test-Path $mirror)) { "MISSING $($_.FullName)" }
} | Select-Object -First 20
```

False-positive note: a deliberately excluded path, a redirected profile folder or a reparse point produces legitimate count differences. Compare against the backup selection policy, not against a naive expectation of equality.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the restore-point timestamp, the closure test result and the observation window start in the same report; a restore without all three is unverified.
- Never treat the backup job's success state as a readiness fact. It is a fact about the job, not about recoverability.
