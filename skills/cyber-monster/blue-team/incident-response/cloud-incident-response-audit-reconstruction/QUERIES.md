# Evidence and Attestation Queries

> Sub-skill: [`cloud-incident-response-audit-reconstruction`](SKILL.md) | Family: **Incident Response**

Queries owned by `cloud-incident-response-audit-reconstruction`, grouped by the reconstruction question they answer. Each class is either a coverage attestation (can this table answer the question at all), a join that attributes an action to a session, or a check that the resulting timeline is reproducible. Verify column names against your own Athena, Log Analytics or BigQuery schema before use.

## Class 1 — Plane coverage and retention boundary

Expected hit: one row per table with its oldest and newest record. The oldest record is the hard left edge of any timeline; anything claimed before it is inference.

```sql
SELECT 'management' AS plane, min(event_time) AS oldest_retained, max(event_time) AS newest_retained, count(*) AS row_count
FROM cloudtrail_management_events
UNION ALL
SELECT 'data' AS plane, min(event_time), max(event_time), count(*)
FROM cloudtrail_data_events
UNION ALL
SELECT 'idp_signin' AS plane, min(created_at), max(created_at), count(*)
FROM idp_signin_logs;
```

False-positive note: a data-event table returning `rows = 0` means data events were never enabled, not that no object was touched; check the trail configuration before writing a scope claim.

## Class 2 — Session separation within one role

Expected hit: several distinct `session_key` values under one role ARN, each with its own time cluster. This is what prevents two actors behind a shared role from being narrated as one.

```sql
SELECT json_extract_scalar(useridentity, '$.arn')                     AS role_arn,
       json_extract_scalar(useridentity, '$.accessKeyId')             AS session_key,
       min(event_time) AS first_observed,
       max(event_time) AS last_observed,
       count(*)        AS total_calls,
       count(DISTINCT event_name) AS operations_used
FROM cloudtrail_management_events
WHERE event_time BETWEEN timestamp '2026-10-01 00:00:00' AND timestamp '2026-11-14 00:00:00'
GROUP BY json_extract_scalar(useridentity, '$.arn'), json_extract_scalar(useridentity, '$.accessKeyId')
HAVING count(*) > 5
ORDER BY first_observed;
```

False-positive note: a long-running service re-assumes the same role on a schedule and produces many short sessions; correlate with the workload's task schedule before treating session multiplicity as multiple actors.

## Class 3 — Cross-source attribution by principal and minute

Expected hit: an IdP sign-in immediately preceding an `AssumeRole` for the same principal, which is what proves a cloud call was human-initiated rather than pre-staged.

```kusto
let win = 10m;
let signins = IdpSigninLogs
  | where TimeGenerated > ago(45d)
  | project signin_time = TimeGenerated, upn = UserPrincipalName,
            src_ip = IPAddress, app = AppDisplayName;
let assumes = AWSCloudTrail
  | where TimeGenerated > ago(45d)
  | where EventName == "AssumeRole"
  | project assume_time = TimeGenerated, role = UserIdentityArn,
            caller = tostring(parse_json(RequestParameters).roleSessionName);
signins
| join kind=inner assumes on $left.upn == $right.caller
| where assume_time between (signin_time .. signin_time + win)
| project signin_time, assume_time, upn, src_ip, role
```

False-positive note: a long-lived session established once and reused for hours will not have a sign-in within ten minutes of every call; absence here is normal for automation and does not imply pre-staged credentials.

## Class 4 — Enumeration and permission-discovery signature

Expected hit: a burst of distinct operations returning `AccessDenied` from one session inside a short interval. This distinguishes probing from use, and it is usually the earliest reliable indicator in a reconstruction.

```sql
SELECT session_key, date_trunc('minute', event_time) AS minute,
       count(*)                          AS attempts,
       count(DISTINCT event_name)        AS distinct_ops,
       sum(CASE WHEN error_code = 'AccessDenied' THEN 1 ELSE 0 END) AS denied
FROM (
  SELECT json_extract_scalar(useridentity, '$.accessKeyId') AS session_key,
         event_time, event_name, error_code
  FROM cloudtrail_management_events
  WHERE event_time > current_timestamp - interval '7' day
)
GROUP BY 1, 2
HAVING sum(CASE WHEN error_code = 'AccessDenied' THEN 1 ELSE 0 END) > 20
   AND count(DISTINCT event_name) > 10
ORDER BY denied DESC;
```

False-positive note: a newly deployed pipeline with an under-scoped role produces exactly this shape on first run; check whether the session key belongs to a principal created within the last day before calling it probing.

## Class 5 — Gap attestation

Expected hit: either no gap, or a gap with a named cause — stopped trail, retention edge, or pending delivery. An unattributed gap invalidates the surrounding narrative.

```bash
# Read-only: compare the trail's last delivery with the export request time,
# then check for a logging-stop event inside the same window.
aws cloudtrail get-trail-status --name "${TRAIL}" --region "${AWS_REGION}" \
  --query "{Logging:IsLogging,Latest:LatestDeliveryTime,Start:StartLoggingTime,Stop:StopLoggingTime}"
aws cloudtrail lookup-events --region "${AWS_REGION}" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "${START_ISO}" --max-items 20 \
  --query "Events[].[EventTime,Username]" --output table
```

False-positive note: `StopLoggingTime` can be populated from a past, planned maintenance window outside the incident; compare its timestamp with the incident window before treating it as actor activity.

## Class 6 — Reproducibility attestation

Expected hit: a stored query text, its parameters, export timestamps and the SHA-256 of each input file, sufficient for a second analyst to regenerate the identical ordering.

```text
attestation_record:
  queries:         exact SQL or KQL text, including window literals
  parameters:      account ids, trail names, table names, timezone
  exports:         file name, byte size, sha256, export_utc
  ordering:        the sort keys used (session_key, ts, request_id)
  expected:        a re-run against the same inputs yields byte-identical order
  blind_spot:      queries that rely on current_timestamp are not reproducible;
                   pin absolute literals before freezing the case
```

False-positive note: an export taken after a retention roll-off cannot be reproduced by anyone, including the original analyst; record the export time so this is visible rather than discovered during review.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Freeze every query with absolute time literals; a reconstruction that depends on a relative window is not reproducible and will not survive review.
