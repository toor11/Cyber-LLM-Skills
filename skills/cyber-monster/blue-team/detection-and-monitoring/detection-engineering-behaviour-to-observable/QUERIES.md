# Detection Queries and Telemetry Artifacts

> Sub-skill: [`detection-engineering-behaviour-to-observable`](SKILL.md) | Family: **Detection and Monitoring**

Every block below answers a translation question: does this sensor emit this action, which fields survive, and what does the benign twin look like. For the parent methodology see [`detection-engineering`](../detection-engineering/SKILL.md); for query-language mechanics see [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md).

## Class 1 — Event-ID inventory on one host

Expected hit: one row per event identifier the agent emitted in the window, with counts. An identifier absent from this list cannot be the observable for a rule on this host.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=LAB-WS01 earliest=-6h@h latest=@h
| stats count AS events, latest(_time) AS last_seen by EventCode
| eval minutes_since = round((now()-last_seen)/60, 0)
| sort EventCode, count
```

False-positive note: a quiet lab host legitimately emits nothing for high-value IDs such as 25 (tampering) or 29 (executable write); confirm the config includes the event before treating silence as a coverage gap.

## Class 2 — Field population and null rate

Expected hit: `null_rate` near zero for the discriminator the rule needs, and a clear picture of which fields the build actually fills. A discriminator at high null rate makes the rule silently miss.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 host=LAB-WS01 earliest=-24h@h latest=@h
| stats count AS total, count(GrantedAccess) AS granted, count(SourceImage) AS source,
        count(TargetImage) AS target, count(CallTrace) AS calltrace
| eval granted_null = round(1 - granted/total, 3), calltrace_null = round(1 - calltrace/total, 3)
| table total, granted_null, calltrace_null
```

False-positive note: `CallTrace` is frequently empty for kernel-originated opens, so a null rate there reflects the source of the call rather than a mapping defect.

## Class 3 — Benign-twin comparison

Expected hit: the same event shape from the benign population, with the discriminating field at a different value or absent. If the benign sample is indistinguishable on every emitted field, the observable cannot support the detection.

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 earliest=-24h@h latest=@h
| eval klass = case(like(lower(SourceImage), "%\\veeam\\%"), "backup",
                     like(lower(SourceImage), "%\\mssense%") OR like(lower(SourceImage), "%\\csfalconservice%"), "security-product",
                     true(), "unclassified-source")
| stats count AS events, values(GrantedAccess) AS masks, dc(SourceImage) AS sources by klass
| sort - events, klass
```

False-positive note: a security product's own self-protection probe uses the same access mask as a credential-dumping tool, which is exactly why the signer or path filter exists; treat its presence as expected rather than as noise.

## Class 4 — Two-event delta for a sequence observable

Expected hit: a distribution of deltas between the participant events, so the rule's `timespan` reflects observed behaviour. A `timespan` chosen without this distribution is a guess.

```kql
let opens = DeviceEvents
| where Timestamp > ago(10080m)
| where ActionType == "OpenProcessApiCall"
| project DeviceId, TargetProcessId=ProcessId, OpenTime=Timestamp, SourceImage=InitiatingProcessFileName;
let spawns = DeviceProcessEvents
| where Timestamp > ago(10080m)
| project DeviceId, ProcessId, SpawnTime=Timestamp, Image=FileName;
opens
| join kind=inner spawns on DeviceId, $left.TargetProcessId == $right.ProcessId
| extend delta_s = datetime_diff('second', SpawnTime, OpenTime)
| summarize count(), percentile(delta_s, 50), percentile(delta_s, 95) by SourceImage
| order by count_ desc
```

False-positive note: table names change between Defender XDR schema versions and lake-tier ingestion hides tables from analytics rules; verify the table exists in the workspace you query before using the distribution.

## Class 5 — Abstraction check: verdict behind raw event

Expected hit: raw events that exist for alerts whose verdict came from the vendor model, so the rule can be re-authored against raw data if the model changes. Where no raw event exists, the detection is permanently coupled to the vendor.

```spl
index=edr sourcetype="edr:detection" earliest=-7d@d latest=@d
| stats count AS verdicts by detection_name, host
| join type=left host
    [ search index=edr sourcetype="edr:raw_event" earliest=-7d@d latest=@d
      | stats count AS raw_events by host ]
| eval coupling = if(isnull(raw_events), "vendor-only", "raw-available")
| stats sum(verdicts) AS verdicts by detection_name, coupling
| sort - verdicts
```

False-positive note: a host with the agent in a reduced-telemetry policy will show `vendor-only` for reasons of policy rather than of sensor design; check the agent policy group before drawing a conclusion about the detection.

## Class 6 — Platform field-name divergence

Expected hit: the same behaviour expressed with different field names per platform, which prevents copy-paste translation between Windows, Linux, and cloud analytics.

```spl
index=linux sourcetype="auditd" earliest=-24h@h latest=@h
| search type=SYSCALL syscall=process_vm_readv OR syscall=ptrace
| stats count AS events, dc(host) AS hosts by syscall, key
| sort - events, klass
```

False-positive note: auditd only records these syscalls when an audit rule selects them; an empty result reflects the audit rule set, not the absence of the behaviour.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the sampled event, its populated field list, the benign counterpart, and the documented loss beside every translation; a rule without that record has an unknown observable.
