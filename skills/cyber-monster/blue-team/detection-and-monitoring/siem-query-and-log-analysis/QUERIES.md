# Detection Queries and Telemetry Artifacts

> Sub-skill: [`siem-query-and-log-analysis`](SKILL.md) | Family: **Detection and Monitoring**

Backend-neutral query classes owned by `siem-query-and-log-analysis`. Each class is written in the dialect most natural to it and states which backend it runs on; the point is the contract behind the query, not the syntax. Platform-specific rewrites belong to the three variant leaves.

## Class 1 — Scope and completeness gate

Expected hit: one row per source present in the window with a plausible document count, plus the job's row/time ceiling so truncation is visible. An absent source invalidates every later class.

```spl
index=* earliest=-24h@h latest=@h
| stats count AS docs, dc(host) AS hosts BY index, sourcetype
| sort - docs
```

```kql
union withsource=tbl *
| where TimeGenerated between (ago(24h) .. now()) and isnotempty(tbl)
| summarize docs = count(), hosts = dcount(Computer) by tbl
| extend docs_per_host = round(docs / max_of(hosts, 1), 1)
| where docs_per_host < 1
```

False-positive note: a source that is quiet and a source that is not onboarded look identical here; confirm against the forwarder or agent inventory before calling it a gap.

## Class 2 — Field model and null-drop visibility

Expected hit: the mapped count close to the total for fields the source guarantees, and a visible unmapped share for fields it does not. A large gap means the aggregation has been silently dropping the very rows it reports on.

```kql
SecurityEvent
| where TimeGenerated between (ago(24h) .. now()) and EventID in (4688, 4689)
| summarize events = count(),
            with_image = countif(isnotempty(Process)),
            with_parent = countif(isnotempty(ParentProcessName)),
            with_cmdline = countif(isnotempty(CommandLine))
| extend image_pct = round(100.0 * with_image / events, 2),
         cmdline_pct = round(100.0 * with_cmdline / events, 2)
```

False-positive note: `CommandLine` is empty for every process event when the audit subcategory does not include command-line capture, so a low percentage there is an audit-policy fact rather than a parser defect.

## Class 3 — Per-key differential

Expected hit: a narrow set of keys whose probe-window count exceeds their own baseline mean by several standard deviations. Everything else is the baseline and is not a finding.

```kql
let baseline = SecurityEvent
| where TimeGenerated between (ago(14d) .. ago(1d))
| where EventID == 4624
| summarize c = count() by Computer, TargetUserName, bin(TimeGenerated, 1d)
| summarize mu = avg(c), sd = stdev(c) by Computer, TargetUserName;
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624
| summarize probe = count() by Computer, TargetUserName
| join kind=inner baseline on Computer, TargetUserName
| where probe > mu + 3*sd and probe > 5
| project Computer, TargetUserName, mu, sd, probe
```

False-positive note: a principal with no baseline history joins to nothing and never appears; list newly seen principals as a separate cohort rather than dropping them silently.

## Class 4 — Sequence and ordering

Expected hit: ordered matches where the anchor event precedes the consequence for the same entity inside a bounded span. No aggregate can produce this class of result.

```eql
sequence by host.name with maxspan=15m
  [ authentication where event.outcome == "failure" and winlog.event_id == 4625 ] with runs=5
  [ authentication where event.outcome == "success" ]
```

False-positive note: a legitimately locked-out user followed by a successful reset produces the same shape; require the success to come from a different source address before escalating.

## Class 5 — Long-window reconciliation

Expected hit: the summary-layer count and the raw count agreeing inside the fully summarised range. Disagreement localises the gap to the summary interval, not to adversary activity.

```spl
| tstats summariesonly=t count FROM datamodel=Authentication.Authentication BY Authentication.user earliest=-30d@d latest=-7d@d
| append [ | tstats summariesonly=f count FROM datamodel=Authentication.Authentication BY Authentication.user earliest=-30d@d latest=-7d@d ]
```

False-positive note: a summary-layer zero means the range was not summarised, never that no events occurred; reconcile before citing any long-window number.

## Class 6 — Cross-backend field resolution

Expected hit: the same semantic resolved to the correct field name per schema before the query runs. ECS and OCSF do not share names, and removed ECS fields return empty without erroring.

```text
semantic            | ECS (current)          | OCSF 1.6 (class-scoped)      | note
--------------------|------------------------|------------------------------|-------------------------
source address      | source.ip              | src_endpoint.ip              | class must be named
process parent pid  | process.parent.pid     | process.parent_pid           | process.pgid removed in ECS 9.0
TLS certificate     | tls.server.x509.*      | tls.certificate.*            | serial_number is base-16
```

False-positive note: a mapping table is not evidence the field is populated; confirm with the Class 2 null-rate before trusting any name in this table.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record which backend each saved query was actually run on; a query transcribed to another backend without re-validation has no evidence behind it.
