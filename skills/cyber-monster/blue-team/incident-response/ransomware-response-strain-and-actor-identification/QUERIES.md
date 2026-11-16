# Evidence Queries and Attestation Artifacts

> Sub-skill: [`ransomware-response-strain-and-actor-identification`](SKILL.md) | Family: **Incident Response**

Queries owned by `ransomware-response-strain-and-actor-identification`. Each class supports one step of hypothesis-then-corroboration: what artifacts exist, what the extension set actually is, which documented behaviours are present locally, and whether more than one deployment exists. Victim-side only — no actor contact, no group attribution from technical artifacts.

## Class 1 — Artifact inventory and preservation state

Expected hit: a per-host row that states which artifact classes survive — note present, encrypted sample present, binary recoverable, endpoint telemetry covering the moment. The class mix decides how strong any later identification can be.

```kql
union
  ( DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName has_any ("README","RESTORE","DECRYPT","HOW_TO","RECOVER")
    | project T=Timestamp, Host=DeviceName, Class="note", Path=FolderPath, Sha=tohex(FileOriginReferrerUrl) ),
  ( DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileRenamed"
    | project T=Timestamp, Host=DeviceName, Class="rename", Path=FolderPath, Sha=FileName ),
  ( DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("-enc","-e ","-pass","--decrypt")
    | project T=Timestamp, Host=DeviceName, Class="process", Path=FolderPath, Sha=tohex(SHA256) )
| summarize Classes=make_set(Class), Artifacts=count(), First=min(T), Last=max(T) by Host
| order by Artifacts desc
```

False-positive note: legitimate recovery utilities, backup agents and EDR remediation tools rename files and carry `-enc` flags. Confirm the process hash and signing state before counting a rename as an encryption artifact.

## Class 2 — Extension inventory against the pre-incident baseline

Expected hit: an extension set in the probe window that is disjoint from the estate's pre-incident inventory, listed with the first-seen timestamp per extension. An extension alone is not an identification; this class exists to establish the artifact, not the family.

```spl
index=edr sourcetype="edr:file" earliest=-72h@h latest=@h
| eval ext=lower(replace(file.name,"^.*(\.[A-Za-z0-9]{2,10})$","\1"))
| eval phase=if(_time < relative_time(now(),"-72h@h"),"baseline","probe")
| stats dc(file.path) as files, min(_time) as first_seen by ext, phase
| stats values(files) as fileset, values(first_seen) as seen by ext
| where mvcount(seen) == 1
| table ext, fileset, seen
| sort - fileset
```

False-positive note: an application upgrade introduces new extensions estate-wide in a single window. Establish whether the extension appears on hosts that had no other incident artifact before treating it as family-compatible.

## Class 3 — Documented-behaviour corroboration

Expected hit: for each candidate family, whether its documented persistence shape is present. This is the class that converts a filename match into a supported attribution — and a clean result here is equally informative and must be reported.

```kql
// Predicted behaviour check: new or modified service with an unsigned or user-writable binary.
let behaviourLookback = 14d;
DeviceProcessEvents
| where Timestamp > ago(behaviourLookback)
| where ProcessCommandLine has_any ("sc create","sc config","New-Service","binPath")
| extend BinPath = extract(@"(?:binPath=|binpath=)\s*""?([^""]+)", 1, ProcessCommandLine)
| where isnotempty(BinPath)
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(behaviourLookback) and ActionType == "FileCreated"
    | project BinPath = FolderPath, Writer = InitiatingProcessAccountName, Created = Timestamp
  ) on BinPath
| project Timestamp, DeviceName, AccountName, BinPath, Writer, ProcessCommandLine
| order by Timestamp asc
```

False-positive note: software deployment agents legitimately create services every patch cycle with the same command shape. Compare the binary path against the deployment tool's staging directory and the account against the sanctioned deployment principal.

## Class 4 — Deployment-boundary test

Expected hit: host groups whose note structure, extension set or contact mechanism differ. One distinct grouping supports a single deployment; two groupings support two, which changes containment scope and should be reported separately.

```spl
index=edr sourcetype="edr:file" earliest=-7d@d latest=@h
| eval ext=lower(replace(file.name,"^.*(\.[A-Za-z0-9]{2,10})$","\1"))
| eval note_name=if(match(lower(file.name),"readme|restore|decrypt|how_to|recover"), lower(file.name), null())
| stats values(ext) as extensions, values(note_name) as notes, dc(host.name) as hosts by host.name
| eventstats dc(extensions) as distinct_sets
| where distinct_sets > 1
| table host.name, hosts, extensions, notes
```

False-positive note: a mixed-OS estate legitimately produces different extension sets per platform, and a partial rollout produces different note names per wave. Group by platform and by deployment wave before concluding two operators.

## Class 5 — Behaviour prediction: staged collection before onset

Expected hit: archive creation on hosts that also show family-compatible artifacts, bounded by the onset. For a family documented to exfiltrate first, this tells you where to look next; the completed-transfer attestation itself is owned by [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/QUERIES.md).

```kql
let onsetUtc = datetime(2026-11-14T02:00:00Z);
let compatibleHosts = DeviceFileEvents
    | where Timestamp between (onsetUtc - 96h .. onsetUtc)
    | where FileName has_any ("README","RESTORE","DECRYPT")
    | summarize by DeviceName;
DeviceFileEvents
| where Timestamp between (onsetUtc - 96h .. onsetUtc)
| where ActionType == "FileCreated"
| extend Ext = tolower(tostring(split(FileName, ".")[-1]))
| where Ext in ("7z","rar","zip","tar","gz")
| where DeviceName in (compatibleHosts)
| summarize Archived = count(), TotalBytes = sum(FileSize) by DeviceName
| extend StageMb = round(TotalBytes / 1048576.0, 1)
| order by StageMb desc
```

False-positive note: hosts that legitimately run archive jobs will appear here whenever they also have a note-like filename from an unrelated application. Confirm the archive's source paths are data repositories, and cross-check the note path against the release manifest before linking staging to the family.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the artifact classes available per host beside any identification claim; a claim made from a note filename alone must be reported as such.
- Preserve note and sample hashes in the case record before any cleanup. Identification cannot be re-derived from deleted artifacts.
