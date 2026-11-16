# Evidence and Attestation Queries

> Sub-skill: [`cloud-incident-response`](SKILL.md) | Family: **Incident Response**

Queries owned by `cloud-incident-response`, grouped by the evidence question they answer. Each class below either proves a log source actually covers the window, proves an actor action occurred, or proves a containment action took effect. Management and data events are separated deliberately: they have different defaults and different retention, and conflating them is the standard way a cloud timeline goes wrong. Verify table and column names against your own Athena, Log Analytics or BigQuery schema.

## Class 1 — Log-estate attestation (run first, every account)

Expected hit: a trail or diagnostic setting whose status is logging, whose scope is multi-region or organisation-wide, whose validation is enabled, and whose destination is owned outside the incident account. Anything else makes the later classes conditional.

```sql
SELECT account_id,
       max(CASE WHEN is_multi_region_trail THEN 1 ELSE 0 END)  AS multi_region,
       max(CASE WHEN log_file_validation_enabled THEN 1 ELSE 0 END) AS validated,
       max(CASE WHEN is_organization_trail THEN 1 ELSE 0 END)  AS org_wide,
       min(event_time) AS oldest_event,
       max(event_time) AS newest_event
FROM aws_cloudtrail_management_events
WHERE event_time > current_timestamp - interval '30' day
GROUP BY account_id;
```

False-positive note: an account with no events looks identical to an account with no trail. Join against the trail configuration inventory before concluding the account was quiet.

## Class 2 — Audit-visibility reduction

Expected hit: any successful logging-stop, trail-delete or validation-disable event, with the actor principal and the destination it pointed at. This class marks the start of a window that no later query can reconstruct.

```sql
SELECT event_time, useridentity_arn, source_ip_address, event_name,
       json_extract_scalar(request_parameters, '$.name') AS trail_name,
       json_extract_scalar(request_parameters, '$.enableLogFileValidation') AS validation
FROM aws_cloudtrail_management_events
WHERE event_name IN ('StopLogging','DeleteTrail','UpdateTrail','DeleteFlowLogs','DeleteEventBus')
  AND error_code IS NULL
  AND event_time > current_timestamp - interval '90' day
ORDER BY event_time DESC;
```

False-positive note: a planned logging migration legitimately produces `UpdateTrail` and a temporary `StopLogging`; the discriminator is a change ticket plus a prompt `StartLogging` in the same window, and usually a destination inside the same account.

## Class 3 — Principal-relative operation anomaly

Expected hit: a small set of operations by principals with no ninety-day history for that operation, or from addresses outside their own historical range. This is the class that survives noisy automation, because it scores the principal against itself.

```sql
WITH hist AS (
  SELECT useridentity_arn, event_name,
         min(source_ip_address) AS min_ip, max(source_ip_address) AS max_ip
  FROM aws_cloudtrail_management_events
  WHERE event_time BETWEEN current_timestamp - interval '90' day
                       AND current_timestamp - interval '2' day
  GROUP BY useridentity_arn, event_name
)
SELECT c.event_time, c.useridentity_arn, c.event_name, c.source_ip_address, c.useragent
FROM aws_cloudtrail_management_events c
LEFT JOIN hist h ON c.useridentity_arn = h.useridentity_arn AND c.event_name = h.event_name
WHERE c.event_time > current_timestamp - interval '24' hour
  AND h.event_name IS NULL
ORDER BY c.event_time DESC
LIMIT 500;
```

False-positive note: a brand-new pipeline role has no history at all and appears here entirely; require at least fourteen days of principal age before scoring, and treat the first appearance as a lead rather than a finding.

## Class 4 — Data-plane access to sensitive stores

Expected hit: object-level read or list events on the sensitive buckets, with the requesting principal and the number of objects touched. If this table is empty, confirm whether data events were enabled before concluding nothing was read.

```sql
SELECT date_trunc('hour', e.event_time) AS hour_bucket,
       e.useridentity_arn               AS reader_principal,
       e.event_name                     AS read_operation,
       count(DISTINCT e.resources[1].ARN) AS objects_touched
FROM cloudtrail_data_events e
WHERE e.event_time > current_timestamp - interval '7' day
  AND e.event_source = 's3.amazonaws.com'
GROUP BY 1, 2, 3
HAVING count(DISTINCT e.resources[1].ARN) > 50
ORDER BY objects_touched DESC;
```

False-positive note: `ListBucket` from a CDN origin-shield or a backup job touches thousands of objects hourly; scope to the sensitive prefix and subtract the documented service principals before scoring breadth.

## Class 5 — Persistence-object inventory

Expected hit: access keys, client secrets, role trust-policy edits and identity-provider changes created inside the incident window, each attributed to a principal. This list is the eradication checklist, and an item left on it re-enters after containment.

```bash
# Read-only inventory of credential-bearing objects created in the window.
aws iam list-users --query "Users[?CreateDate>='${START_ISO}'].[UserName,CreateDate]" --output table
aws iam list-roles  --query "Roles[?CreateDate>='${START_ISO}'].[RoleName,CreateDate]"  --output table
aws iam list-access-keys --output table
```

False-positive note: normal onboarding creates users and keys every day; compare against the joiner list from the identity system, and treat only unattributed objects as persistence.

## Class 6 — Containment effect attestation

Expected hit: the revocation event itself, followed by either `AccessDenied` for the actor's principal or an absence of successful calls from it. A policy attachment with no subsequent denial is an unproven containment.

```kusto
let revokedAt = datetime(2026-11-14T10:00:00Z);
AWSCloudTrail
| where TimeGenerated between (revokedAt - 2h .. revokedAt + 4h)
| where UserIdentityArn has "compromised-role"
| summarize calls = count(),
            allowed  = countif(isempty(ErrorCode)),
            denied   = countif(ErrorCode == "AccessDenied")
  by Window = bin(TimeGenerated, 15m)
| extend deny_ratio = round(denied * 1.0 / attempts, 3)
| sort by Window asc
```

False-positive note: a revoked role can still succeed for up to roughly thirty seconds while the deny policy propagates, by design; successes inside that bound are expected and must be timestamped rather than read as failure.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, beside each query, whether it depends on management events or data events, because the two have different coverage defaults and a data-event query over a period without data logging returns a misleading zero.
