# Detection Queries and Telemetry Artifacts

> Sub-skill: [`endpoint-detection-and-edr-operations`](SKILL.md) | Family: **Detection and Monitoring**

Blocks use the Microsoft Defender XDR advanced-hunting table names (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceEvents`, `DeviceInfo`) as a concrete field model; substitute your agent's equivalents after confirming the column set. For query-language mechanics see [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md).

## Class 1 — Sensor and policy baseline per device

Expected hit: one row per device with a recent check-in, a current policy version, and the sensor state. Devices missing here make every later negative conditional, which is why this class runs first.

```kusto
DeviceInfo
| where Timestamp between (ago(1d) .. now())
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceName, OSPlatform, OSVersion,
          SensorHealthState, OnboardingStatus, LastSeen = Timestamp,
          MachineGroup, JoinType
| where LastSeen < ago(2h) or SensorHealthState != "Active"
| order by LastSeen asc, DeviceName asc
```

False-positive note: a laptop that is powered off overnight has a stale check-in and is not a sensor fault; join against the asset inventory's expected online hours before escalating.

## Class 2 — Process lineage with creation times

Expected hit: children whose reported parent image is a document handler, a script host, or a browser, with plausible creation times. A child whose creation time precedes the parent's indicates reparenting.

```kusto
DeviceProcessEvents
| where Timestamp between (ago(1d) .. now())
| extend parent = tostring(InitiatingProcessFileName)
| extend parent_time = todatetime(InitiatingProcessCreationTime)
| where parent in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mshta.exe","wscript.exe","chrome.exe")
| extend lineage_ok = ProcessCreationTime >= parent_time
| project Timestamp, DeviceName, AccountName, parent, parent_time,
          FileName, ProcessCreationTime, lineage_ok, ProcessCommandLine
| order by Timestamp desc, DeviceName asc
```

False-positive note: `InitiatingProcessCreationTime` can be empty for processes whose creator exited before the agent captured metadata; an empty value is not evidence of tampering.

## Class 3 — Actions joined on identifier and start time

Expected hit: network, file, and registry events for one process instance. Joining on identifier alone mixes processes on a busy host, so the creation time is part of the key.

```kusto
let target = DeviceProcessEvents
| where Timestamp between (ago(6h) .. now())
| where FileName =~ "rundll32.exe"
| project DeviceId, TargetProcessId=tostring(ProcessId), Created=ProcessCreationTime, Cmd=ProcessCommandLine;
target
| join kind=inner hint.strategy=broadcast (
    DeviceNetworkEvents
    | where Timestamp > ago(6h)
    | project DeviceId, ProcessId=tostring(InitiatingProcessId),
              ConnTime=Timestamp, RemoteUrl, RemoteIP, RemotePort
  ) on DeviceId, $left.TargetProcessId == $right.ProcessId
| where ConnTime >= Created
| project Created, DeviceId, TargetProcessId, Cmd, ConnTime, RemoteUrl, RemoteIP
| order by ConnTime desc
```

False-positive note: the joining column must be cast to the same type on both sides; a string-to-int mismatch returns zero rows and looks exactly like no activity.

## Class 4 — Fleet peer differential

Expected hit: lineage pairs or command-line shapes present on a handful of devices. A behaviour on one or two hosts is an outlier; the same behaviour on the whole fleet is administration.

```kusto
DeviceProcessEvents
| where Timestamp between (ago(7d) .. now())
| summarize devices=dcount(DeviceId), executions=count(),
            first=min(Timestamp), last=max(Timestamp)
            by FileName, InitiatingProcessFileName, AccountName
| where devices <= 3 and executions >= 1
| order by executions desc
```

False-positive note: a lab or engineering group of three hosts legitimately runs unusual tooling; join the device to its machine group before scoring the count as rarity.

## Class 5 — Cross-plane agreement with flow records

Expected hit: endpoint network events that also appear in the flow record for the same destination and minute, and the inverse list of connections only the flow record saw. The second list localises the blind spot.

```spl
index=edr sourcetype="edr:network" earliest=-24h@h latest=@h
| stats count AS edr_events by host, dest_ip, dest_port
| join type=full host, dest_ip, dest_port
    [ search index=netflow sourcetype="conn:summary" earliest=-24h@h latest=@h
      | stats count AS flow_records by src_host AS host, dst_ip AS dest_ip, dst_port AS dest_port ]
| eval only_flow = if(isnull(edr_events), 1, 0), only_edr = if(isnull(flow_records), 1, 0)
| stats sum(only_flow) AS flow_only, sum(only_edr) AS edr_only, count AS pairs by host
| sort - flow_only
```

False-positive note: the flow sensor may see east-west traffic that the agent's network events exclude by policy; a `flow_only` count is a policy question before it is an evasion finding.

## Class 6 — Independent-channel corroboration

Expected hit: Sysmon process-tampering or executable-write events that the EDR plane also recorded, or that only Sysmon saw. The second case is the finding that matters.

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=25 OR EventCode=29) earliest=-7d@d latest=@d
| stats count AS events, values(Image) AS images, dc(host) AS hosts by EventCode, host
| sort - events, host
```

False-positive note: EventID 29 fires for every executable written to a selected path, including installer output; treat it as a staging indicator that requires the writing process's context, not as a detection on its own.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Deploy endpoint rules with the policy version they assume; a rule written for a policy that does not record the event category is silent rather than broken.
