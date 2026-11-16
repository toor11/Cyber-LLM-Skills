# Detection Queries and Telemetry Artifacts

> Sub-skill: [`alert-tuning-and-false-positive-reduction`](SKILL.md) | Family: **Detection and Monitoring**

Queries here operate on the *alert and disposition record*, not on raw security telemetry, because tuning is measured on alerts a rule produced and an analyst judged. Field names below assume a normalized detection index (`index=detections`) and a case store; substitute your own names after confirming extraction, and read the SPL pipeline notes in [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) if the base-search semantics are unfamiliar.

## Class 1 — Disposition coverage per rule (run first)

Expected hit: one row per rule that fired in the window, with a non-zero `judged` count and a `judged_share` close to 1. Any rule whose `judged_share` is below roughly 0.5 cannot be tuned from data and must be labelled first.

```spl
index=detections sourcetype="alert:disposition" earliest=-30d@d latest=@d
| eval judged = if(isnotnull(disposition) AND disposition!="open", 1, 0)
| stats count AS fired, sum(judged) AS judged, dc(alert_id) AS alerts by rule_id, rule_version
| eval judged_share = round(judged/fired, 3)
| sort judged_share
```

False-positive note: an `open` disposition is not a false positive, and counting it as one inflates the apparent noise floor; keep `open` in its own bucket and exclude it from every precision figure.

## Class 2 — Rationale mining for exclusion candidates

Expected hit: a small number of `benign_entity` values concentrating most of the false-positive volume for one rule. Those rows name the exclusion's subject; rows with a single alert are anecdote and should not drive a change.

```spl
index=detections sourcetype="alert:disposition" rule_id="*" earliest=-30d@d latest=@d
| where disposition=="false_positive" AND isnotnull(benign_entity)
| stats count AS fp_alerts, values(case_note) AS notes by rule_id, benign_entity
| eventstats sum(fp_alerts) AS rule_fp_total by rule_id
| eval share_of_rule_fp = round(fp_alerts/rule_fp_total, 3)
| where fp_alerts >= 20 AND share_of_rule_fp >= 0.05
| sort - fp_alerts
```

False-positive note: `benign_entity` is analyst-typed and drifts in spelling; normalise it against the asset inventory or CMDB before you aggregate, or one jump host will appear as four different entities.

## Class 3 — Shadow-mode differential before shipping the exclusion

Expected hit: `suppressed` matching the Class 2 estimate within a few percent, and `surviving` still above zero. A `suppressed` count far above the estimate means the predicate is bleeding into unrelated traffic.

```spl
index=detections sourcetype="alert:rule_fire" rule_id="cred_dump_lsass_access" earliest=-14d@d latest=@d
| eval candidate = if((like(lower(src_user), "svc_backup%") AND like(lower(parent_image), "%veeam%")), 1, 0)
| bin _time span=24h
| stats count AS fired, sum(candidate) AS suppressed by _time
| eval surviving = fired - suppressed
| eventstats avg(surviving) AS surviving_avg, avg(suppressed) AS suppressed_avg
| table _time, fired, suppressed, surviving, surviving_avg, suppressed_avg
```

False-positive note: the tag must be applied in the rule's own search, not retro-fitted over the alert index, or late-arriving alerts are classified by a predicate that did not exist when they fired.

## Class 4 — Re-fire regression against labelled positives

Expected hit: at least one hit per fixture (`fixture_id`) that the rule was authored to catch. A fixture row with `hits=0` is a coverage regression and blocks the tune regardless of the volume result.

```spl
index=detections sourcetype="fixture:positive" rule_id="cred_dump_lsass_access" earliest=-7d@d latest=@d
| eval hit = if(isnotnull(matched_rule_id), 1, 0)
| stats sum(hit) AS hits, count AS fixture_events by fixture_id, technique_id
| where hits == 0
```

False-positive note: a fixture that never contained the triggering event in the first place also reports `hits=0`; validate each fixture against the pre-change rule and only regression-test fixtures that fired before the edit.

## Class 5 — Exclusion-field null audit

Expected hit: `null_share` near zero for every sourcetype the rule reads. A high `null_share` means the exclusion predicate can never match, so the rule keeps firing while the change is recorded as delivered.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-12h@h latest=@h
| stats count AS total, count(ParentImage) AS parent_mapped, count(TargetUserName) AS user_mapped
| eval parent_null_share = round(1 - parent_mapped/total, 3)
| eval user_null_share = round(1 - user_mapped/total, 3)
| where parent_null_share > 0.01 OR user_null_share > 0.01
```

False-positive note: Sysmon event 1 carries `ParentImage`; native Security 4688 carries `ParentProcessName` and `CreatorProcessName` depending on audit policy, so a null reading may be a wrong field name rather than a missing value.

## Class 6 — Post-change drift watch

Expected hit: a flat daily `fired` series after the change, with no step back up. A return to pre-change volume within days usually means a parser change re-mapped the excluded field or the benign population moved hosts.

```spl
index=detections sourcetype="alert:rule_fire" rule_id="cred_dump_lsass_access" earliest=-30d@d latest=@d
| bin _time span=24h
| stats count AS fired by _time
| eventstats median(fired) AS med_before by rule_version
| where fired > med_before * 2 AND rule_version=="v3-excl-svcbackup"
```

False-positive note: compare across a version boundary only after the deployment timestamp is recorded; a version label applied retroactively to historical alerts will show phantom drift.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Attach the rationale count, the shadow-replay numbers, and the re-fire pass count to the change record; an exclusion without those three numbers is not deployable.
