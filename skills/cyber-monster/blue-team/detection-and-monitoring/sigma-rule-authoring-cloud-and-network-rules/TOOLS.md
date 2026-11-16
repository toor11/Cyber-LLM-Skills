# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sigma-rule-authoring-cloud-and-network-rules`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for proving a cloud or network rule has input, then converting it. Never invent commands or flags — check `aws <service> help` and `sigma list pipelines` on the installed versions, because provider APIs and pipeline names change independently.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `aws cloudtrail get-event-selectors` | `aws cloudtrail get-event-selectors --trail-name <trail>` | Prove whether management and data events are actually captured for the rule's operation class | Cross-platform (AWS CLI) |
| `aws cloudtrail describe-trails` | `aws cloudtrail describe-trails --include-shadow-trails` | Enumerate trails and their scope, catching an account not covered by the organisation trail | Cross-platform (AWS CLI) |
| `aws logs filter-log-events` | `aws logs filter-log-events --log-group-name <group> --filter-pattern '<pattern>' --max-items 1` | Pull one real event to read the actual field paths before authoring | Cross-platform (AWS CLI) |
| `sigma convert` (cloud) | `sigma convert -t sentinel -p microsoft_xdr rules/cloud/cloudtrail_stop_logging.yml` | Convert a cloud rule and inspect the generated source and operation clause | Cross-platform |
| `sigma convert` (network) | `sigma convert -t splunk -p splunk_network rules/network/proxy_traversal.yml` | Convert a proxy or DNS rule for an on-prem pipeline | Cross-platform |
| `jq` | Filter a captured record to the paths the rule needs before writing the selection | Confirm a nested path exists instead of guessing at it | Linux, macOS, Windows |

## Minimal Script Shape

The shape below is the minimum defensible cloud-rule gate: prove the subscription, read the real field paths, then convert and inspect the source clause.

```bash
#!/usr/bin/env bash
# cloud-sigma-gate.sh — subscription gate, field-path gate, conversion gate.
set -euo pipefail

TRAIL="${TRAIL:?cloudtrail trail name}"
SERVICE="${SERVICE:-s3.amazonaws.com}"
LOG_GROUP="${LOG_GROUP:?cloudtrail cloudwatch log group}"
RULE="${RULE:?path to the sigma rule}"

# 0. Subscription gate: management events must be on, and data resources must
#    exist if the rule targets object-level operations.
aws cloudtrail get-event-selectors --trail-name "$TRAIL" \
  | jq -e '.EventSelectors[] | select(.IncludeManagementEvents == true)' >/dev/null \
  || { echo "GAP: management events not captured -> INCONCLUSIVE (Telemetry Gap)"; exit 2; }

# 1. Field-path gate: read one real event for the service and list its leaf paths.
aws logs filter-log-events --log-group-name "$LOG_GROUP" \
  --filter-pattern "{ \$.eventSource = \"${SERVICE}\" }" --max-items 1 \
  | jq -r '.events[0].message | fromjson | paths(scalars) | join(".")' \
  | sort -u > /tmp/ct_paths.txt
test -s /tmp/ct_paths.txt \
  || { echo "GAP: no captured event for ${SERVICE} -> rule input unproven"; exit 3; }

# 2. Conversion gate: the generated query must name the provider source.
CONVERTED="$(sigma convert -t sentinel -p microsoft_xdr "$RULE")"
printf '%s\n' "$CONVERTED"
printf '%s' "$CONVERTED" | grep -qi 'AWSCloudTrail' \
  || { echo "GAP: pipeline did not map the cloud service for this rule"; exit 4; }
```

## Notes That Prevent Wrong Runs

- `get-event-selectors` on an organisation trail describes the org trail, not every member account's shadow trails; use `--include-shadow-trails` before concluding a region or account is covered.
- `filter-log-events` with a CloudWatch filter pattern returns matches from the log group's own ingestion; a group that lags will look empty even when the trail is healthy.
- Conversion for a cloud pipeline can succeed while mapping only the product and not the service; always inspect the source clause in the converted output.
- A proxy rule converted for one vendor's field names does not transfer to another proxy; author per logsource rather than fanning one selection across vendors.
