# Evidence Queries and Attestation Artifacts

> Sub-skill: [`raas-extortion-and-negotiation-triage`](SKILL.md) | Family: **Incident Response**

Queries owned by `raas-extortion-and-negotiation-triage`. Each class answers one part of the exfiltration question — did a transfer complete, what was staged, what was read at the data plane, does the content carry an obligation, and which planes were absent. Victim-side only; no actor contact and no negotiation content.

## Class 1 — Transfer completion, not byte volume

Expected hit: a completed transfer to a destination outside the sanctioned bulk-egress set, with size and completion status on the same row. Rows without completion status are attempts, and attempts are not exfiltration.

```kql
let onset = datetime(2026-11-14T02:00:00Z);
let sanctioned = dynamic(["storage.corp.example", "backup.corp.example", "cdn.corp.example"]);
CommonSecurityLog
| where TimeGenerated between (onset - 96h .. onset)
| extend Dest = coalesce(DestinationHostName, DestinationIP)
| where Dest !in (sanctioned)
| summarize Attempts = count(), Completed = countif(DeviceAction in ("allow","accept")),
            Bytes = sum(SentBytes), First = min(TimeGenerated), Last = max(TimeGenerated)
    by Src = SourceIP, Dest, Url = RequestURL, Proto = ApplicationProtocol
| extend Verdict = case(
    Completed > 0 and Bytes > 10000000, "completed - assess content",
    Completed > 0, "completed small - assess plausibility",
    "attempt only - not exfiltration")
| order by Bytes desc
| take 40
```

False-positive note: sanctioned-set drift is the dominant failure. A new CDN or a newly provisioned storage account appears as an unsanctioned destination and looks like exfiltration on the day it is onboarded; refresh the set from the egress allowlist of record, not from memory.

## Class 2 — Staging manifest reconstruction

Expected hit: archive files whose names map to internal repositories, shares or application exports, with creation time and size. This supports an inference about intent and volume; it does not by itself prove the archive left the estate.

```spl
index=edr sourcetype="edr:file" earliest=-96h@h latest=@h
| eval archiveTool=lower(coalesce(process.name,Image))
| where match(archiveTool,"rar|7z|zip|tar|makecab")
| stats sum(size) as staged_bytes, count as archives, min(_time) as first_staged,
        values(file.path) as paths by host.name, user.name
| eval staged_mb=round(staged_bytes/1048576,1)
| where staged_mb > 50
| table host.name, user.name, archives, staged_mb, first_staged
| sort - staged_mb
```

False-positive note: build pipelines, log rotation and DBA maintenance produce large archives continuously. Require the archive's source paths to include data repositories rather than build outputs, and confirm the archiver is first-seen on that host.

## Class 3 — Data-plane read by an unauthorised principal

Expected hit: an object-storage or database audit entry where the reading principal is external, unexpected, or using a credential that belongs to another service. A completed read at the data plane is exfiltration evidence in its own right and does not depend on egress telemetry.

```kql
let sanctionedPrincipals = dynamic(["svc-backup@corp.example", "svc-analytics@corp.example"]);
let readLookback = 96h;
let blobReads = StorageBlobLogs
    | where TimeGenerated > ago(readLookback)
    | where OperationName in ("GetBlob","GetBlobProperties","ListBlobs")
    | extend Principal = tostring(parse_json(Authentication).identity)
    | where Principal !in (sanctionedPrincipals)
    | project T=TimeGenerated, Plane="object-store", Principal, Src=CallerIpAddress,
              Target=AccountName, Bytes=ResponseBodySize, Op=OperationName;
let s3Reads = AWSCloudTrail
    | where TimeGenerated > ago(readLookback)
    | where EventName in ("GetObject","ListObjects","ListObjectsV2")
    | project T=TimeGenerated, Plane="s3", Principal=UserIdentityArn, Src=SourceIpAddress,
              Target=ResourceName, Bytes=tolong(AdditionalEventData.bytesTransferredIn), Op=EventName;
union blobReads, s3Reads
| summarize Reads=count(), Bytes=sum(Bytes), First=min(T), Last=max(T) by Plane, Principal, Src, Target
| order by Bytes desc
```

False-positive note: newly deployed automation and rotated service principals appear as unfamiliar names until the identity inventory catches up. Corroborate with a change record before treating a first read as exfiltration.

## Class 4 — Classification join: does the content carry an obligation?

Expected hit: a row per transferred or staged object set showing the owning application, the classification of the data, and therefore which notification regime applies. This is the join that turns a technical finding into a legal one.

```spl
index=dataclass sourcetype="dataclass:inventory" earliest=-1d@d latest=@d
| eval path_key=lower(coalesce(repository_path, share_path))
| join type=left path_key
    [ search index=edr sourcetype="edr:file" earliest=-96h@h latest=@h
      | eval path_key=lower(file.path)
      | stats sum(size) as bytes, values(user.name) as principals by path_key ]
| where isnotnull(bytes)
| stats sum(bytes) as staged_bytes, dc(path_key) as paths,
        values(classification) as classes, values(owner_app) as apps by path_key
| eval regulated=if(match(mvjoin(classes,","),"PII|PHI|PCI|restricted|confidential"),"YES","NO")
| table owner_app, classes, regulated, paths, staged_bytes
| sort - staged_bytes
```

False-positive note: classification catalogues are usually incomplete, and an unclassified path is not a non-regulated path. A missing classification means the obligation question is open, not answered; say which.

## Class 5 — Plane-availability attestation

Expected hit: an explicit statement, per plane, of whether it existed for the pre-encryption window. This class produces the sentence that belongs in the disclosure record when the answer is inconclusive.

```kql
let windowStart = datetime(2026-11-10T00:00:00Z);
let windowEnd = datetime(2026-11-14T02:00:00Z);
union
  ( CommonSecurityLog | where TimeGenerated between (windowStart .. windowEnd)
    | summarize n=count() by Plane="proxy/firewall" ),
  ( StorageBlobLogs | where TimeGenerated between (windowStart .. windowEnd)
    | summarize n=count() by Plane="object-store" ),
  ( AWSCloudTrail | where TimeGenerated between (windowStart .. windowEnd)
    | summarize n=count() by Plane="cloud-control-plane" ),
  ( Syslog | where TimeGenerated between (windowStart .. windowEnd) and ProcessName has "postfix"
    | summarize n=count() by Plane="mail-flow" )
| extend Status = if(n > 0, "present", "ABSENT for window")
| project Plane, Status, n
```

False-positive note: a plane can be present and still not cover the window — collection may have started mid-incident. Check the first event timestamp per plane, not merely a non-zero count.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Maintain the sanctioned bulk-egress destination list as configuration, with an owner and a review cadence; every class above depends on it.
- Record plane availability beside every exfiltration conclusion. The difference between "no transfer found" and "no telemetry existed" is the difference between a defensible notification and a regulatory finding.
