# Evidence Queries and Attestation Artifacts

> Sub-skill: [`post-incident-review-and-lessons`](SKILL.md) | Family: **Incident Response**

Queries owned by `post-incident-review-and-lessons`. Each class produces a measurement or an attestation the review record needs: intervals from confirmed timestamps, factor coverage across cases, action closure evidence, recurrence detection, and telemetry-continuity for long lookbacks.

## Class 1 — Interval measurement from confirmed timestamps

Expected hit: one row per interval — dwell, detect, triage, contain, recover — each calculated from timestamps that have a source, with inferred ones excluded. This is the only defensible input to a trend.

```spl
index=incident sourcetype="incident:timeline" case_id="IR-2026-0417"
| eval confirmed=if(confidence=="confirmed","yes","no")
| where confirmed=="yes"
| stats min(eval(if(marker=="first_execution", _time, null()))) as t0,
        min(eval(if(marker=="first_detection", _time, null()))) as t1,
        min(eval(if(marker=="acknowledged", _time, null()))) as t2,
        min(eval(if(marker=="containment_effective", _time, null()))) as t3,
        min(eval(if(marker=="recovered", _time, null()))) as t4
| eval dwell_h=round((t1-t0)/3600,1), triage_m=round((t2-t1)/60,0),
       contain_m=round((t3-t2)/60,0), recover_h=round((t4-t3)/3600,1)
| table t0, t1, t2, t3, t4, dwell_h, triage_m, contain_m, recover_h
```

False-positive note: a marker recorded from recollection rather than a log is not confirmed even when it is typed into the timeline with confidence "confirmed". Require the source field to name a log record, ticket field or platform alert before accepting a marker.

## Class 2 — Contributing-factor coverage across comparable cases

Expected hit: for each factor, whether it is present in the failed case only, in both cases, or in neither. A factor present in both the failed and the better-handled case is context, not cause.

```kql
let cases = datatable(case_id:string, outcome:string, egress_inspection:bool, svc_write_to_backup:bool, alert_rota:bool)
[
  "IR-2026-0417", "failed",   false, true,  false,
  "IR-2025-0912", "contained", false, false, true
];
cases
| extend factors = pack_array(
    iff(egress_inspection, "egress_inspection", ""),
    iff(svc_write_to_backup, "svc_write_to_backup", ""),
    iff(alert_rota, "alert_rota", ""))
| mv-expand factors to typeof(string)
| where isnotempty(factors)
| summarize Present = make_set(case_id) by factors
| extend Verdict = case(array_length(Present) == 2, "context - present in both",
                        "cause candidate - present in failed case only")
```

False-positive note: two cases rarely differ in exactly one factor, so a "cause candidate" here is a hypothesis that still needs a mechanism. State the mechanism, or downgrade the finding to a contributing factor.

## Class 3 — Action closure evidence

Expected hit: for each closed action, the verification artefact — a passing test, an injected event that fired, a re-run of the failed scenario. An action with no verification record is not closed regardless of its ticket state.

```kql
let actions = datatable(id:string, owner:string, due:datetime, ticket_state:string, verify_test:string, verify_result:string)
[
  "A-01", "dba-lead", datetime(2026-12-01), "closed", "write_attempt_must_fail", "pass",
  "A-02", "soc-mgr",  datetime(2026-11-28), "closed", "inject_alert_ack_under_10m", "pass",
  "A-03", "netsec",   datetime(2027-01-15), "closed", "replay_beacon_must_alert", ""
];
actions
| extend GenuinelyClosed = (ticket_state == "closed" and verify_result == "pass")
| extend Status = case(GenuinelyClosed, "verified",
                       ticket_state == "closed" and isempty(verify_result), "REOPEN - closed without test",
                       "open")
| project id, owner, due, Status, verify_test, verify_result
```

False-positive note: a passing test that was run before the change was deployed proves nothing. Require the verification timestamp to be later than the change deployment time.

## Class 4 — Recurrence detection

Expected hit: incidents sharing a contributing factor with a prior incident whose action was closed. Recurrence is evidence that the earlier closure was administrative rather than technical.

```spl
index=incident sourcetype="incident:review" earliest=-730d@d latest=@d
| stats values(case_id) as cases, values(action_ids) as actions, dc(case_id) as n by root_factor
| where n > 1
| eval recurring=if(n > 1, "YES", "NO")
| table root_factor, n, cases, actions, recurring
| sort - n
```

False-positive note: a generic factor label such as "phishing" will group unrelated incidents. Factors must be specific enough to be actionable — "service account could write to backup tier" rather than "excessive privilege".

## Class 5 — Telemetry continuity for long-lookback intervals

Expected hit: an explicit statement of whether the decisive interval is inside the retention of the plane that would evidence it. Where Defender tables stream to the Microsoft Sentinel data lake, the workspace may hold nothing beyond the Defender retention window while the lake holds years.

```kql
// Workspace side: what does the SIEM actually hold for the interval?
union withsource=TableName DeviceProcessEvents, DeviceNetworkEvents, SecurityEvent
| where TimeGenerated between (ago(180d) .. ago(31d))
| summarize Rows=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by TableName
| extend Note = case(Rows == 0, "workspace empty for interval - check data-lake routing", "workspace has data")
```

False-positive note: an empty workspace result is routinely read as "no activity". Where tables are lake-only, they are invisible to Sentinel analytics rules and the Logs blade, so the workspace query returns nothing while the data exists elsewhere. Query the lake endpoint and record which one produced the answer.

## Deployment Gates

- Measure intervals only from timestamps that name a source record; a review built on recollection produces a trend that moves for reasons unrelated to capability.
- Require a verification artefact before closing any action, and check its timestamp against the deployment time.
- Record which data plane answered each long-lookback question, because workspace and lake retention differ and the difference changes the finding.
