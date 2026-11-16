# Detection Queries and Telemetry Artifacts

> Sub-skill: [`cloud-detection-and-logging`](SKILL.md) | Family: **Detection and Monitoring**

Every block below presupposes that the audit destination and its selector were enumerated first. Queries are written against a normalised table (`cloudtrail_events`) and a lake-style SQL dialect; substitute your own warehouse's names, and use [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) when the base search semantics are the actual question. Field names follow CloudTrail JSON (`useridentity.arn`, `eventname`, `sourceipaddress`, `requestparameters`) after normalisation.

## Class 1 — Coverage and selector assertion (run first)

Expected hit: one row per account/region destination showing the trail or diagnostic setting as active, multi-region if required, with the event classes it actually selects. A destination that stops days ago, or that omits data events for the resource in scope, invalidates every later class.

```sql
SELECT account_id, region, trail_name, is_multi_region_trail, is_organization_trail,
       has_management_events, has_data_events, latest_delivery_time
FROM cloudtrail_trail_status
WHERE latest_delivery_time < CURRENT_TIMESTAMP - INTERVAL '2' HOUR
   OR has_data_events = false
ORDER BY latest_delivery_time ASC
```

False-positive note: a fresh trail or a destination created inside the last two hours has no delivery yet; compare against the destination's creation time before recording a coverage failure.

## Class 2 — First-seen action per principal against baseline

Expected hit: a short list of `(principal, eventname)` pairs present in the probe window and absent from the equally long baseline. High-yield rows are credential, policy, key, and network changes by principals that normally do none of those.

```kql
let base = CloudTrail
| where TimeGenerated between (ago(720h) .. ago(24h))
| summarize n=count() by UserIdentityArn=to string(UserIdentityArn), EventName;
let probe = CloudTrail
| where TimeGenerated > ago(1440m)
| summarize n=count(), first=min(TimeGenerated) by UserIdentityArn=to string(UserIdentityArn), EventName;
probe
| join kind=leftanti base on UserIdentityArn, EventName
| where n >= 1
| order by first desc nulls last
```

False-positive note: a principal whose role was recreated gets a new ARN and therefore a fully novel action set; resolve the ARN to a role name before treating novelty as behaviour change.

## Class 3 — Data-plane access when the selector is proven

Expected hit: object-level events naming the specific resource and the requesting session. If this class returns nothing while the selector from Class 1 is verified as covering the resource, the result is meaningful; if the selector does not cover it, the block is inapplicable rather than empty.

```sql
SELECT eventtime, useridentity.arn AS principal, useridentity.sessioncontext.sessionissuer.username AS issuer,
       eventname, requestparameters.bucketName AS bucket, requestparameters.key AS object_key,
       sourceipaddress, useragent
FROM cloudtrail_events
WHERE eventname IN ('GetObject','PutObject','GetSecretValue','BatchGetItem')
  AND eventtime BETWEEN TIMESTAMP '2026-11-13 00:00:00' AND TIMESTAMP '2026-11-14 00:00:00'
  AND requestparameters.bucketName = 'finance-exports-prod'
ORDER BY eventtime
```

False-positive note: replication, lifecycle transition, and backup jobs read objects continuously; exclude by session issuer or user agent only after confirming which role the platform service uses, or the exclusion also covers an attacker using the same role.

## Class 4 — Role-chain and session origin

Expected hit: an `AssumeRole` followed by actions whose source address or user agent differs from the assuming caller. The mismatch is the finding; a chain that stays on one address and one user agent is ordinary workload behaviour.

```sql
WITH assume AS (
  SELECT eventtime, useridentity.arn AS assumer, requestparameters.rolearn AS assumed_role,
         requestparameters.roleSessionName AS session_name, sourceipaddress, useragent
  FROM cloudtrail_events
  WHERE eventname = 'AssumeRole'
    AND eventtime >= TIMESTAMP '2026-11-13 00:00:00'
),
used AS (
  SELECT useridentity.sessioncontext.sessionissuer.arn AS assumed_role,
         MIN(sourceipaddress) AS min_ip, MAX(sourceipaddress) AS max_ip,
         COUNT(DISTINCT sourceipaddress) AS ip_count, COUNT(*) AS actions,
         MIN(eventtime) AS first_action, MAX(eventtime) AS last_action
  FROM cloudtrail_events
  WHERE useridentity.type = 'AssumedRole'
    AND eventtime >= TIMESTAMP '2026-11-13 00:00:00'
  GROUP BY useridentity.sessioncontext.sessionissuer.arn
)
SELECT a.assumer, a.assumed_role, a.session_name, a.sourceipaddress AS assume_ip,
       u.ip_count, u.actions, u.first_action, u.last_action
FROM assume a JOIN used u ON a.assumed_role = u.assumed_role
WHERE u.ip_count > 1
ORDER BY u.actions DESC
```

False-positive note: a role assumed by a CI runner legitimately acts from a rotating pool of egress addresses; map the pool's published ranges before treating multiple source addresses as a stolen session.

## Class 5 — Azure activity scope differential

Expected hit: a principal whose operation mix differs sharply between subscriptions, or an operation type appearing in a subscription where it has never appeared. This catches activity a single-subscription view cannot see.

```kql
AzureActivity
| where TimeGenerated > ago(168h)
| summarize ops=dcount(OperationNameValue), calls=count(),
            examples=make_set(OperationNameValue, 8)
            by Caller, SubscriptionId, bin(TimeGenerated, 1d)
| join kind=innerunique (
    AzureActivity
    | where TimeGenerated between (ago(30d) .. ago(7d))
    | summarize base_ops=dcount(OperationNameValue) by Caller, SubscriptionId
  ) on Caller, SubscriptionId
| where ops > base_ops * 2 and calls > 10
```

False-positive note: a newly onboarded subscription has no baseline, so every operation looks novel; require the baseline row to be non-null before scoring the ratio.

## Class 6 — Finding-to-event corroboration

Expected hit: the provider finding joined to at least one audit event with the same principal and resource inside the finding's time bracket. A finding that cannot be joined has no grounded request behind it and remains a lead.

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| project TimeGenerated, AlertName, CompromisedEntity, ProviderName, ResourceId=tostring(Entities)
| join kind=leftouter hint.strategy=broadcast (
    CloudTrail
    | where TimeGenerated > ago(7d)
    | project EventTime=TimeGenerated, UserIdentityArn=tostring(UserIdentityArn), EventName
  ) on $left.CompromisedEntity == $right.UserIdentityArn
| where isempty(EventName)
```

False-positive note: the detector may fire on VPC flow or DNS telemetry rather than on an audit event, so an unjoined finding proves the join is inapplicable rather than that the finding is false.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the destination, selector, retention, and account scope beside every deployed cloud rule; a rule deployed against an unverified selector fails silently rather than loudly.
