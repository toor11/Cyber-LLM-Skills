# Detection Queries and Telemetry Artifacts

> Sub-skill: [`log-source-onboarding-and-parsing`](SKILL.md) | Family: **Detection and Monitoring**

Contract checks owned by `log-source-onboarding-and-parsing`. These run against the destination store and the collector, not against the producer, so they can be executed before any detection claims coverage. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Emission, delivery and arrival reconciliation

Expected hit: three numbers within a small margin for the same hour — producer-side counter, collector `sent` metric, destination document count. Divergence localises the broken stage.

```spl
| tstats count WHERE index=firewall BY _time span=1h
| appendcols [ search index=collector_metrics source=otel:receiver_sent earliest=-24h@h
  | timechart span=1h sum(value) AS sent ]
| eval delta_pct = round(100*(count-sent)/sent, 1)
| where abs(delta_pct) > 5
```

False-positive note: a legitimate backfill or replay inflates one hour without any loss; compare adjacent hours and check the collector restart time before declaring a gap.

## Class 2 — Null-rate per required field (baseline versus probe)

Expected hit: near-zero null-rate for contractually required fields in both windows, and a visible jump for the field whose parser branch broke. Conditional fields must be excluded or scoped.

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4624
| bin _time span=1d
| stats count AS total, count(TargetUserName) AS user_ok, count(IpAddress) AS ip_ok BY _time
| eval user_null_pct = round(100*(total-user_ok)/total, 2)
| eval ip_null_pct = round(100*(total-ip_ok)/total, 2)
| where user_null_pct > 5 OR ip_null_pct > 50
```

False-positive note: `IpAddress` is legitimately `-` for interactive console logons, so a high null-rate on that field alone is expected; scope to LogonType 3 and 10 before treating it as parser drift.

## Class 3 — Dataset routing and schema-class collapse

Expected hit: the expected `event.dataset` present with a stable per-day count, and OCSF `class_uid` distributed across the classes the source should produce. A single class for all events means the class filter is too broad.

```eql
// Elastic EQL: any event from the vendor whose dataset is one we do not recognise.
any where observer.vendor == "fortinet" and not event.dataset in
  ("fortinet.firewall", "fortinet.utm", "fortinet.event")
```

```text
FROM logs-*
| WHERE observer.vendor == "fortinet"
| STATS events = COUNT(*) BY event.dataset
| SORT events ASC
```

False-positive note: a brand-new dataset with a tiny count is usually a version bump introducing one extra event type, not a routing failure; confirm with a raw sample before reassigning parsers.

## Class 4 — Pipeline rejects and dead letters

Expected hit: zero or a small, explained number of rejected documents. Any reject on a security-relevant event type is an immediate coverage hole.

```bash
# Elastic ingest pipeline failures, last 24h
curl -s -u "$ES_AUTH" "$ES_HOST/_index/failed-logs/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-24h"}}},
       "aggs":{"by_error":{"terms":{"field":"error.type","size":10}}}}' | jq .
```

False-positive note: a rejected document is not evidence an event did not occur — the raw event may still sit in an archive or the collector buffer; recover before concluding absence.

## Class 5 — Freshness and late arrival

Expected hit: p95 `ingest_time - event_time` below the rule's window budget. Above that, a rule with a tight window is structurally blind to the source.

```kql
CommonSecurityLog
| where TimeGenerated between (ago(48h) .. now()) and isnotempty(DeviceCustomDate1)
| extend lag_min = datetime_diff('minute', TimeGenerated, todatetime(DeviceCustomDate1))
| summarize p50=percentile(lag_min,50), p95=percentile(lag_min,95), late=countif(lag_min > 15) by DeviceVendor
| order by p95 desc
```

False-positive note: appliances with unsynchronised clocks report negative lags; verify NTP on a sample device before attributing lag to the pipeline.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Store the gate results with the source's onboarding record; a later empty result must be attributable to a named gate rather than to "no activity".
