# Detection Queries and Telemetry Artifacts

> Sub-skill: [`security-metrics-and-detection-coverage`](SKILL.md) | Family: **Detection and Monitoring**

Metric computations owned by `security-metrics-and-detection-coverage`. Each class produces one defensible number with its denominator attached; none of them detect adversary activity. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — MTTD from first evidence, with the undetected cohort separated

Expected hit: a p50/p95 latency distribution over incidents that have a documented `first_evidence_utc`, plus a separate count of incidents with no estate detection at all. Averaging the two cohorts together is the error this class prevents.

```kql
SecurityIncident
| where TimeGenerated > ago(180d) and Status == "Closed"
| extend mttd_min = datetime_diff('minute', todatetime(FirstAlertUtc), todatetime(FirstEvidenceUtc))
| summarize p50=percentile(mttd_min, 50), p95=percentile(mttd_min, 95),
            n=count(), undetected=countif(isempty(FirstEvidenceUtc))
  by Severity
| extend note = "undetected cohort excluded from p50/p95 and reported separately"
```

False-positive note: if `FirstEvidenceUtc` is populated from the alert's own timestamp the metric is `alert-to-analysis`, not MTTD; check the field's provenance before publishing.

## Class 2 — MTTR split by phase

Expected hit: total response time decomposed into detection-to-triage, triage-to-containment and containment-to-closure. A single MTTR hides whether the programme is slow at analysis or at approval.

```spl
index=itsm sourcetype="incident:workflow" earliest=-180d@d
| stats min(eval(if(state="detected",_time,null()))) AS t_detect,
        min(eval(if(state="triaged",_time,null()))) AS t_triage,
        min(eval(if(state="contained",_time,null()))) AS t_contain,
        max(_time) AS t_close BY incident_id, severity
| eval triage_min=round((t_triage-t_detect)/60,1),
       contain_min=round((t_contain-t_triage)/60,1),
       close_min=round((t_close-t_contain)/60,1)
| stats median(triage_min) AS p50_triage, median(contain_min) AS p50_contain,
        median(close_min) AS p50_close BY severity
```

False-positive note: incidents that skip a state entirely produce null phase durations; count them and report the skip rate rather than imputing a value.

## Class 3 — Precision and volume per rule

Expected hit: worked-alert counts with a true-positive ratio, so a rule can be judged on both noise and value. A rule with high precision and two alerts per quarter is not the same asset as one with high precision and daily coverage.

```spl
index=soar sourcetype="alert:disposition" earliest=-90d@d
| stats count AS worked,
        count(eval(disposition="true_positive")) AS tp,
        count(eval(disposition="benign")) AS benign,
        count(eval(disposition="undetermined")) AS undetermined BY rule_name
| eval precision = round(tp/worked, 3)
| eval worked_per_day = round(worked/90, 2)
| where precision < 0.05 OR worked_per_day < 0.02
| sort precision
```

False-positive note: a rule that has never been worked has no precision at all — `undetermined` is not `benign`. Report the unreviewed share alongside the ratio.

## Class 4 — Coverage tier arithmetic

Expected hit: the same technique set counted at four tiers — library, deployed, collected, validated — so the drop between tiers is visible. Publishing only the top number is what this class replaces.

```kql
let relevant = _GetWatchlist('relevant_techniques') | project technique_id;
let rules = _GetWatchlist('rule_inventory')
    | project rule_id, technique_id, enabled, source_table;
let contract = _GetWatchlist('source_contract')
    | project source_table, passing;
let validated = _GetWatchlist('emulation_results')
    | where fired == true | distinct technique_id;
relevant
| join kind=leftouter (rules) on technique_id
| join kind=leftouter (contract) on source_table
| join kind=leftouter (validated) on technique_id
| extend tier = case(
    technique_id in (validated), "validated",
    passing == true, "collected",
    enabled == true, "deployed",
    isnotempty(rule_id), "library",
    "gap")
| summarize techniques=count() by tier
| extend pct_of_relevant = round(100.0*techniques/toscalar(relevant | count), 1)
```

False-positive note: a technique mapped to several rules takes the highest tier it reaches; counting it once per rule inflates every tier above `library`.

## Class 5 — Rule staleness and decay

Expected hit: rules with zero alerts over the period, or with a failing test fixture. Both are coverage that exists on paper only.

```eql
// Elastic EQL: enabled rules whose own execution metadata reports a failure.
any where event.category == "configuration" and rule.enabled == true
  and rule.status in ("failed", "warning")
```

```kql
AlertEvidence
| where TimeGenerated > ago(90d)
| summarize alerts = count() by RuleName
| join kind=rightouter (_GetWatchlist('rule_inventory') | project RuleName, enabled) on RuleName
| where isnull(alerts) and enabled == true
| project RuleName, alerts, enabled
```

False-positive note: a low-volume but high-value rule can legitimately produce zero alerts in 90 days; pair the check with the rule's design intent before recommending retirement.

## Class 6 — Time-to-coverage across framework change

Expected hit: median and p90 days from a technique's publication in a framework release to a deployed detection, computed per technique class. The v18-to-v19 relabel is the obvious stress case.

```text
technique_class | median_days_to_deploy | p90_days | notes
----------------|-----------------------|----------|----------------------------------------
credential      | 41                    | 96       | v19 relabel of T1562 family pending
execution       | 28                    | 74       | -
defense impair. | 132                   | 210      | TA0112 split not yet reflected in rules
```

False-positive note: techniques that no data source in the estate can expose have no achievable deployment time; exclude them from the median and count them as accepted gaps.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Store the metric inputs, not only the outputs; a number whose inputs were not retained cannot be recomputed with the same definitions next quarter.
