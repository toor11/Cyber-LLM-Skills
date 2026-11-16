# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cloud-detection-and-logging`](SKILL.md) | Family: **Detection and Monitoring**

Read-only inventory and query entry points across the three major providers. Every command below inspects configuration or reads events; none mutates a trail, selector, or policy. Verify flags against the installed CLI version — the AWS CLI v2 and the Azure CLI move subcommands between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| AWS CLI v2 | `aws cloudtrail describe-trails --include-shadow-trails --region eu-west-1` | Enumerate trails, including shadow trails from other accounts that write into this account | Any host with AWS CLI |
| AWS CLI v2 | `aws cloudtrail get-trail-status --name org-trail --region eu-west-1` | Prove the trail is delivering, with `LatestDeliveryTime` and `IsMultiRegionTrail` | Any host with AWS CLI |
| AWS CLI v2 | `aws cloudtrail get-event-selectors --trail-name org-trail --region eu-west-1` | Read the exact management and data-event selectors that decide what the trail records | Any host with AWS CLI |
| AWS CLI v2 | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey --start-time 2026-11-13T00:00:00Z --max-results 50` | Bounded management-event lookup, one attribute at a time, last 90 days per region | Any host with AWS CLI |
| CloudTrail Lake SQL | `aws cloudtrail start-query --query-statement "SELECT eventname, useridentity.arn FROM <eds-id> WHERE eventtime > '2026-11-13 00:00:00'"` | Multi-account, multi-region SQL over events in an event data store | Any host with AWS CLI |
| Azure CLI | `az monitor activity-log list --start-time 2026-11-13T00:00:00Z --max-events 100 --query "[].{op:operationName.value, caller:caller, sub:subscriptionId}"` | Read Activity Log entries for a scope, filtered by time | Any host with Azure CLI |
| Azure CLI | `az monitor diagnostic-settings list --resource <resource-id>` | Prove which log categories and destinations a resource actually sends | Any host with Azure CLI |
| GCP `gcloud` | `gcloud logging sinks list --project <project>` then `gcloud logging read 'logName:"cloudaudit.googleapis.com"' --freshness=1d --limit=50` | Enumerate audit sinks and read admin-activity entries without exporting to a warehouse | Any host with gcloud |
| `sigma-cli` | `sigma convert -t sentinel -p azure_monitor rules/cloud/` | Compile a cloud Sigma rule for a KQL backend so the deployed query can be reviewed | Cross-platform |

## Minimal Script Shape

The script asserts coverage before it answers the question, and it refuses to report an empty data-plane result without naming the selector state.

```bash
#!/usr/bin/env bash
# cloud-coverage-gate.sh — prove the audit plane, then answer one scoped question.
set -euo pipefail

TRAIL="${TRAIL:?set TRAIL to the trail name}"
REGION="${REGION:-eu-west-1}"

# 1. Is the destination alive, and what does it actually select?
STATUS=$(aws cloudtrail get-trail-status --name "$TRAIL" --region "$REGION" \
  --query '{latest:LatestDeliveryTime,multi:IsMultiRegionTrail,org:IsOrganizationTrail}' --output json)
SELECTORS=$(aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" --output json)

python3 - "$STATUS" "$SELECTORS" <<'PY'
import json, sys
status = json.loads(sys.argv[1])
sel = json.loads(sys.argv[2])
data_events = [s for s in sel.get("AdvancedEventSelectors", []) if s.get("Name", "").startswith("Data")]
print("latest_delivery:", status.get("latest"))
print("multi_region:", status.get("multi"), "org_trail:", status.get("org"))
print("data_event_selectors:", len(data_events))
if not status.get("latest"):
    sys.exit("INCONCLUSIVE (Coverage Gap): trail has never delivered")
if not data_events:
    sys.exit("INCONCLUSIVE (Data-Plane Gap): no data-event selector; do not answer object-level questions")
print("PASS: control plane verified, data plane selector present")
PY

# 2. Scoped management-event question, one attribute at a time.
aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time 2026-11-13T00:00:00Z --max-results 50 \
  --query 'Events[].{t:EventTime,who:Username,src:CloudTrailEvent}' --output json
```

## Notes That Prevent Wrong Runs

- `lookup-events` returns a capped page and accepts one lookup attribute at a time; paging with `--next-token` is required before any count is treated as complete.
- Event history and `LookupEvents` cover management and Insights events within a bounded recent window per region. They are not a substitute for a trail when the question spans weeks or needs data events.
- Organization-level trails and organization event data stores are created from the management or delegated-administrator account and are not visible to member accounts; run the query where the destination lives.
- CloudTrail Lake availability has changed for new customers; confirm the current status in your region and account type before designing a detection around an event data store. Where Lake is unavailable, use the organization trail into your own warehouse.
- `az monitor activity-log list` is scope-bound and time-filtered; cross-subscription questions require iterating subscriptions or querying the exported Log Analytics workspace instead.
