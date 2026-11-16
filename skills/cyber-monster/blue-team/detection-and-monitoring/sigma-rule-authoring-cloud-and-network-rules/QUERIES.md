# Detection Queries and Telemetry Artifacts

> Sub-skill: [`sigma-rule-authoring-cloud-and-network-rules`](SKILL.md) | Family: **Detection and Monitoring**

Cloud and network rule checks owned by `sigma-rule-authoring-cloud-and-network-rules`. These verify that a rule has input before anyone debates its logic: subscription present, field path real, operation name current. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Captured-event field paths

Expected hit: the field the rule selects on appears in a real event from that exact service and log type. A path borrowed from another service's documentation never matches.

```bash
# Pull one real event and list its leaf paths before authoring the selection.
aws logs filter-log-events \
  --log-group-name "$TRAIL_GROUP" \
  --filter-pattern '{ $.eventSource = "cloudtrail.amazonaws.com" }' \
  --max-items 1 \
  | jq -r '.events[0].message | fromjson | paths(scalars) | join(".")' | sort -u
```

```text
# Expected shape for a CloudTrail record (subset):
eventSource
eventName
userIdentity.arn
userIdentity.type
sourceIPAddress
requestParameters.bucketName
responseElements.bucketPolicy
errorCode
```

False-positive note: `paths(scalars)` returns empty for null values, so a legitimately absent optional field looks like a missing path; check the raw message before concluding the field does not exist.

## Class 2 — Subscription tier for the operation

Expected hit: the trail or log profile captures the operation class the rule targets. Data-plane operations require an explicit selector; without one the rule has no input.

```bash
aws cloudtrail describe-trails --include-shadow-trails \
  | jq -r '.trailList[] | {Name, S3BucketName, IsMultiRegionTrail, HasCustomEventSelectors}'
```

```bash
aws cloudtrail get-event-selectors --trail-name "$TRAIL" \
  | jq -r '.EventSelectors[] | {ReadWriteType, IncludeManagementEvents, DataResources}'
```

False-positive note: an empty `DataResources` array is the normal shape for a management-only trail; it is a gap only if the rule targets object-level or item-level operations.

## Class 3 — Operation-name inventory and drift

Expected hit: every operation the rule lists exists in the window, and no near-identical operation name appears that the rule misses. Provider APIs add operations between versions.

```kql
AWSCloudTrail
| where TimeGenerated between (ago(30d) .. now()) and EventSource == "s3.amazonaws.com"
| summarize calls = count(), principals = dcount(SourceIpAddress) by EventName
| where EventName startswith "Delete" or EventName startswith "PutBucket"
| order by calls desc
```

False-positive note: an operation with zero calls in 30 days may simply be unused in this estate; absence from the list is not evidence the rule's name is wrong. Confirm the name against the provider's own API reference for the account's region and version.

## Class 4 — Proxy field availability

Expected hit: the proxy emits the field the rule selects on, in the transaction records the rule needs. Enforcement-only logging yields only blocked transactions.

```spl
index=proxy sourcetype="bluecoat:proxysg" earliest=-24h@h
| stats count AS events, dc(src) AS clients BY cs_action, sc_status
| sort - events
```

False-positive note: `cs_action` values differ per vendor and per firmware; a value the rule assumes may be spelled differently, so read the distribution rather than the documentation.

## Class 5 — DNS telemetry shape

Expected hit: the resolver logs the query type and response code for the names in scope. Sampled or cache-miss-only logging cannot prove absence.

```spl
index=dns sourcetype="dns:query" earliest=-24h@h
| stats count AS queries, dc(src) AS clients, values(answer) AS answers BY query_type, rcode
| where rcode != 0 OR clients <= 2
```

False-positive note: a resolver that logs only cache misses shows a lower query count than the endpoint actually issued; compare against endpoint-side DNS evidence before treating a low count as absence.

## Class 6 — Rule conversion for a cloud pipeline

Expected hit: converted text naming the provider's source and the operation field. A rule that converts to a generic placeholder will never match.

```bash
sigma convert -t sentinel -p microsoft_xdr rules/cloud/cloudtrail_stop_logging.yml
```

```bash
sigma convert -t splunk -p splunk_aws rules/cloud/cloudtrail_stop_logging.yml
```

False-positive note: a pipeline may map `product: aws` but not `service: cloudtrail`; check the converted source clause rather than assuming the pair is supported.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the subscription tier, the captured field paths and the conversion command with every deployed cloud or network rule.
