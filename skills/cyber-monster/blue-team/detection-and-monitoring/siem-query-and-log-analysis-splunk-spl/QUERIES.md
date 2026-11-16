# Detection Queries and Telemetry Artifacts

> Sub-skill: [`siem-query-and-log-analysis-splunk-spl`](SKILL.md) | Family: **Detection and Monitoring**

SPL owned by `siem-query-and-log-analysis-splunk-spl`. Each block is grouped by query class. Every class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Field names are the Splunk CIM / add-on names; confirm them against your own `props.conf` and data models first.

## Class 1 — Coverage and retention (run before any other class)

Expected hit: one row per onboarded sourcetype with a plausible time range. A sourcetype that is absent, or whose range ends days ago, invalidates every later class.

```text
| metadata type=sourcetypes index=* | table sourcetype, totalCount, firstTime, lastTime
| metadata type=hosts index=wineventlog | where (now() - recentTime) > 3600
```

False-positive note: a quiet sourcetype and an uncollected sourcetype look identical here; cross-check with the forwarder or agent inventory before declaring a gap.

## Class 2 — Base-search correctness (field present vs field unmapped)

Expected hit: `mapped` greater than zero with `unmapped` explaining the remainder. A large `unmapped` share means the field is missing from extraction and any `by`-clause over it under-counts.

```text
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 earliest=-24h@h latest=@h
| stats count AS total, count(TargetUserName) AS mapped | eval unmapped = total - mapped
| rex field=_raw "SubjectUserName=(?<subject>\S+)" | stats dc(subject) AS subjects_in_raw
```

False-positive note: `rex` recovering a value proves the string is in raw text, not that the schema carries it; keep the distinction in the report rather than switching the query to `rex` permanently.

## Class 3 — Per-key aggregate differential

Expected hit: a stable baseline distribution, with a small set of keys whose probe-window count exceeds baseline mean plus three standard deviations. Only those keys are candidates; everything else is the baseline.

```text
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 earliest=-14d@d latest=@d
| eval k = coalesce(src, ComputerName)."|".coalesce(TargetUserName,"-")
| bin _time span=1d | stats count AS c by _time, k
| eventstats avg(c) AS mu, stdev(c) AS sd by k
| where c > mu + (3*sd) AND c > 5 | sort - c
```

False-positive note: a new host or new service account enters with no baseline and always trips `c > 5`; require at least five baseline days for a key before scoring it.

## Class 4 — Acceleration reconciliation

Expected hit: `summariesonly=t` and `summariesonly=f` counts agree inside the fully summarized range. Disagreement localises the range to acceleration lag, not to adversary activity.

```text
| tstats summariesonly=t count FROM datamodel=Endpoint.Processes BY Processes.dest earliest=-7d@d latest=@d
| tstats summariesonly=f count FROM datamodel=Endpoint.Processes BY Processes.dest earliest=-7d@d latest=@d
```

False-positive note: `summariesonly=t` returning zero rows means "no summaries in this range", never "no process ran"; never publish that zero as a negative finding.

## Class 5 — Ordering and sequence

Expected hit: transactions whose duration and event count match the defined shape, with the `startswith` anchor present. `stats` cannot produce this class of result at all.

```text
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=1102 OR EventCode=4719) earliest=-24h@h latest=@h
| transaction ComputerName maxspan=15m startswith=(EventCode=4719) endswith=(EventCode=1102)
| where duration <= 900 | table ComputerName, duration, eventcount
```

False-positive note: group-policy refresh legitimately rewrites audit policy on schedule; require the transaction to be followed by log clearing or by a change that disables a specific subcategory.

## Class 6 — Subsearch truncation check

Expected hit: the outer search returns rows, and the job inspector reports no `maxout`/`maxtime` truncation. Truncation is a telemetry limit, not a verdict.

```text
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-24h@h latest=@h
  [ search index=wineventlog EventCode=4688 earliest=-7d@d latest=-1d@d
    | stats count by NewProcessName | where count > 0 | fields NewProcessName | format ]
| stats count by NewProcessName, Account_Name
```

False-positive note: a legitimately large allow/deny list will always truncate a subsearch; move it to a `lookup` or `inputlookup` table before trusting a zero-result outer search.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the search branch (base, `stats`, `tstats`, `transaction`) and the acceleration state next to every saved search; a reviewer must be able to tell whether a zero was measured or assumed.
