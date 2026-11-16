# Detection Queries and Telemetry Artifacts

> Sub-skill: [`detection-engineering`](SKILL.md) | Family: **Detection and Monitoring**

Queries about the detection programme itself: which sensors emit the artifact an analytic needs, how much noise a deployed rule produces, and which analytics nobody works. Base-search semantics are documented in [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md); rule-conversion mechanics live in [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md).

## Class 1 — Artifact visibility per platform

Expected hit: one row per platform and sensor showing the event identifier present with a recent timestamp. A platform with no row for the artifact cannot host the analytic, so any rule deployed there is silent by construction.

```spl
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h@h latest=@h
| stats count AS events, dc(host) AS hosts, latest(_time) AS last_seen by EventCode
| eval hours_since = round((now() - last_seen)/3600, 1)
| where EventCode IN (1,3,11,22,25,29)
| sort EventCode, host
```

False-positive note: a quiet lab segment legitimately produces no EventID 25 or 29 events; the absence of a high-value event is not a configuration gap until you compare against the config's include rules for that event.

## Class 2 — Rule precision sample

Expected hit: a per-rule false-positive share computed from hand-labelled alerts in a fixed window, with the dominant rationale named. This is the only number that describes what the queue experiences.

```spl
index=detections sourcetype="alert:disposition" earliest=-7d@d latest=@d
| eval judged = case(isnull(disposition), 0, disposition=="open", 0, true(), 1)
| stats count AS fired, sum(eval(if(disposition=="false_positive",1,0))) AS fp, sum(judged) AS judged by rule_id
| eval fp_share = round(fp/nullif(judged,0), 3), judged_share = round(judged/nullif(fired,0), 3)
| where fp_share > 0.3 OR judged_share < 0.5
| sort - fp_share
```

False-positive note: a rule with fewer than twenty judged alerts cannot support a share estimate; read it as a small sample and say so rather than ranking it against rules with hundreds.

## Class 3 — Exclusion cost and narrowing check

Expected hit: the daily volume of events an exclusion suppresses, next to the daily volume that still passes. An exclusion that suppresses nearly everything in its field is not tuning; it is removal.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-14d@d latest=@d
| eval excluded = if(like(lower(ParentImage), "%\\veeam\\%") OR like(lower(Account_Name), "svc_backup%"), 1, 0)
| eval eng_day = strftime(_time, "%Y-%m-%d")
| stats count AS total, sum(excluded) AS suppressed by eng_day
| eval surviving = total - suppressed, suppressed_share = round(suppressed/total, 3)
| table eng_day, total, suppressed, surviving, suppressed_share
```

False-positive note: a backup window concentrates suppression into one hour, so the daily share understates it; check the hourly distribution before approving the exclusion.

## Class 4 — Correlation window sanity

Expected hit: the distribution of event-pair deltas for the referenced rules, showing where the chosen `timespan` sits relative to real behaviour. A `timespan` narrower than the observed p95 misses the behaviour; one far wider catches unrelated co-occurrence.

```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) earliest=-7d@d latest=@d
| eval kind = if(EventCode==4625, "fail", "success")
| stats min(eval(if(kind=="fail",_time,null()))) AS first_fail,
        min(eval(if(kind=="success",_time,null()))) AS first_success
        by src_ip, TargetUserName
| eval delta_s = first_success - first_fail
| where delta_s > 0
| stats count, p50(delta_s) AS p50, p95(delta_s) AS p95, max(delta_s) AS worst by src_ip
| sort - count, rule_id
```

False-positive note: service accounts with retry logic produce fail-then-success pairs continuously; exclude known retry principals before using the distribution to size a `timespan`.

## Class 5 — Staleness and orphaned analytics

Expected hit: rules with zero dispositions in the review window, and rules whose mapped technique no longer exists in the current ATT&CK release. Both are candidates for retirement rather than tuning.

```spl
index=detections sourcetype="rule:catalog" earliest=-2d@d latest=@d
| stats latest(technique_id) AS technique, latest(deploy_time) AS deployed, latest(review_date) AS reviewed by rule_id
| join type=left max=0 rule_id
    [ search index=detections sourcetype="alert:disposition" earliest=-31d@d latest=@d
      | stats count AS judged by rule_id ]
| eval days_reviewed = round((now()-reviewed)/86400, 0)
| where isnull(judged) OR days_reviewed > 180
| sort days_reviewed
```

False-positive note: a rule for a genuinely rare behaviour should be quiet; distinguish "never fires because rare" from "cannot fire" by replaying its positive fixture before retiring it.

## Class 6 — Compiled-query diff across backends

Expected hit: a diff confined to syntax and field-mapping differences. A semantic difference — a dropped `NOT`, a modifier that becomes a substring match — means the detection is not the same detection on that backend.

```bash
sigma convert -t splunk -p splunk_windows rules/cred_access_lsass.yml > /tmp/cred.spl
sigma convert -t sentinel -p sentinel_windows rules/cred_access_lsass.yml > /tmp/cred.kql
diff -u /tmp/cred.spl /tmp/cred.kql || true
```

False-positive note: the two dialects differ in almost every token, so a raw diff is unreadable; compare the selection condition and the exclusion list rather than the whole text.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record strategy, analytic, platform, and depth beside every rule; a rule without a mapping cannot be assessed when the framework version moves.
