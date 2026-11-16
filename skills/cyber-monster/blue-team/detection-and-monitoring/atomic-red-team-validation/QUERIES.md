# Detection Queries and Telemetry Artifacts

> Sub-skill: [`atomic-red-team-validation`](SKILL.md) | Family: **Detection and Monitoring**

Validation queries here are narrow by design: they are scoped to one host, one principal, and a run window bracketed around a single atomic execution. Generic hunting patterns belong to the parent skills — see [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) for base-search semantics and [`detection-engineering`](../detection-engineering/SKILL.md) for authoring contracts. Confirm field names against your onboarded schema before relying on any of the blocks below.

## Class 1 — Prereq and sensor pre-state

Expected hit: one row per target host with a recent agent check-in and a non-zero baseline event count for the channel the test needs. A zero baseline means the sensor is not delivering and the run cannot be interpreted.

```spl
index=edr sourcetype="edr:agent_status" earliest=-24h@h latest=@h
| stats latest(last_checkin) AS last_seen, latest(policy_version) AS policy by host
| eval age_min = round((now() - last_seen)/60, 0)
| where age_min > 60 OR isNull(last_seen)
```

False-positive note: a host that is powered off, in a maintenance window, or re-imaged reports a stale check-in identical to a broken agent; confirm the host is supposed to be online before calling it a coverage gap.

## Class 2 — Raw artifact harvest inside the run window

Expected hit: at least one event for the technique's artifact, on the target host, from the executing principal, timestamped inside the bracketed window. This row is the one that proves the sensor saw the probe.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4698 earliest=-15m latest=now
| search ComputerName="LAB-WS01"
| eval within = if(_time >= relative_time(now(), "-10m"), 1, 0)
| table _time, ComputerName, SubjectUserName, TaskName, TaskContent, within
| sort - _time
```

False-positive note: event time is parsed from the record's own timestamp, so a host with a skewed clock places its artifact outside the bracket; compare against `_indextime` before declaring the harvest empty.

## Class 3 — Alert correlation for the expected rule

Expected hit: at least one alert row whose rule identifier matches the one under test, for the same host and principal as the Class 2 harvest. A different rule identifier means a neighbouring analytic fired and the rule under test is still unvalidated.

```spl
index=detections sourcetype="alert:rule_fire" earliest=-15m latest=now
| search dest_host="LAB-WS01"
| stats count AS fires, values(rule_id) AS rules, min(_time) AS first_fire by dest_host, src_user
| where fires > 0
```

False-positive note: a rule that also fires on unrelated background activity will show a hit during the window regardless of the probe; compare the pre-run window from Class 4 before attributing the alert to the atomic.

## Class 4 — Pre/post channel differential

Expected hit: a rate change confined to the run window and to the artifact's own event identifier, returning to baseline afterwards. A channel that was already busy with the same artifact cannot attribute the probe.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4698 ComputerName="LAB-WS01" earliest=-60m latest=now
| bin _time span=5m
| stats count AS events by _time
| eventstats median(events) AS baseline
| eval delta = events - baseline
| table _time, events, baseline, delta
```

False-positive note: group-policy-driven task creation and patch management both create 4698 events on a schedule; if the baseline already carries them on a fixed cadence, the delta belongs to that cadence, not the probe.

## Class 5 — Cleanup verification

Expected hit: zero rows created after the cleanup timestamp for the artifact class the test produced. Residue here becomes a standing false positive for every analyst and contaminates the next exercise.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4698 ComputerName="LAB-WS01" earliest=-2h latest=now
| eval after_cleanup = if(_time > relative_time(now(), "-30m"), 1, 0)
| stats count AS tasks by TaskName, after_cleanup
| where after_cleanup == 1
```

False-positive note: the cleanup command itself writes events; distinguish the removal event from a creation event by the event identifier and the acting principal rather than by host alone.

## Class 6 — Compiled-rule replay of the harvested event

Expected hit: the compiled backend query returns the harvested event when replayed against the harvest window. A compiled query that returns nothing while the YAML rule looks correct localises the gap to conversion or pipeline handling.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-11-14T18:00:00Z) .. datetime(2026-11-14T18:20:00Z))
| where DeviceName =~ "LAB-WS01"
| where ProcessCommandLine has_any ("schtasks", "Register-ScheduledTask")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

False-positive note: this table is a Defender XDR advanced-hunting table; if it is ingested only into the Sentinel data lake tier, analytics rules and the Logs blade will not see it and the replay will appear empty for reasons unrelated to the rule.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the technique, test number, prereq outcome, run window, harvest result, alert result, and cleanup verification in one record; a validation without all seven fields is not reproducible.
