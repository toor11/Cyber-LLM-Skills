# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cloud-incident-response-audit-reconstruction`](SKILL.md) | Family: **Incident Response**

Verified entry points for extracting, joining and freezing cloud audit records. Every command is a read or a query: nothing here changes account state. Confirm exact flag spelling with `<tool> --help` on the installed version, particularly `jq` filter quoting across shells and `athena` workgroup requirements.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| AWS CLI (`cloudtrail`) | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --start-time <iso> --end-time <iso> --max-items 1000 --output json` | Bounded management-event extraction within the ninety-day history, pageable | Any host with AWS credentials |
| Amazon Athena | `aws athena start-query-execution --query-string "<sql>" --query-execution-context Database=cloudtrail_db --result-configuration OutputLocation=s3://<bucket>/recon/` | Run the join SQL against the CloudTrail table without loading data locally | Any host with AWS credentials |
| AWS CLI (`s3`) | `aws s3api list-objects-v2 --bucket <log-bucket> --prefix "AWSLogs/<acct>/CloudTrail/" --query "Contents[?LastModified>='<iso>'].[Key,Size]"` | Enumerate which log objects exist and therefore which hours are present | Any host with AWS credentials |
| `jq` | `jq -r ".Events[].CloudTrailEvent" events.json` | Unwrap the nested event string so session and event fields become selectable | Linux, macOS, Windows |
| Azure CLI | `az monitor activity-log list --start-time <iso> --end-time <iso> --query "[].{t:eventTimestamp,op:operationName.value,caller:caller,id:correlationId}" -o json` | Subscription control-plane records with correlation id for the join | Any host with Azure credentials |
| gcloud CLI | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"' --freshness=30d --format=json --limit=1000` | Admin Activity records with `protoPayload.requestMetadata.callerSuppliedUserAgent` for attribution | Any host with gcloud credentials |
| `sha256sum` / `Get-FileHash` | `sha256sum exports/*.json > SHA256SUMS` | Freeze inputs so the timeline is reproducible and tamper-evident | Linux, macOS, Windows |

## Minimal Script Shape

The shape below extracts, flattens and freezes a management-event window. It refuses to write a timeline when the extraction returned no records for an interval that the trail claims to cover, because that combination is a gap rather than a quiet period.

```bash
#!/usr/bin/env bash
# timeline-extract.sh - read-only extraction with a coverage gate and frozen hashes.
set -euo pipefail

START="${START_ISO:?ISO8601 window start}"
END="${END_ISO:?ISO8601 window end}"
OUT="${OUT_DIR:?output directory}"
TRAIL="${TRAIL:?trail name}"
REGION="${AWS_REGION:?region}"

mkdir -p "$OUT"

# 1. Coverage gate: refuse to build a timeline on a trail that is not delivering.
aws cloudtrail get-trail-status --name "$TRAIL" --region "$REGION" \
  --query "{Logging:IsLogging,Latest:LatestDeliveryTime}" --output json > "$OUT/trail-status.json"
if ! grep -q '"Logging": true' "$OUT/trail-status.json"; then
  echo "GAP: trail not logging; timeline would describe an absence, not activity" >&2
  exit 2
fi

# 2. Extract management events for the window.
aws cloudtrail lookup-events \
  --start-time "$START" --end-time "$END" --max-items 5000 \
  --region "$REGION" --output json > "$OUT/events-raw.json"

# 3. Flatten to a session-keyed timeline; keep the plane column explicit.
jq -r '.Events[].CloudTrailEvent | fromjson
       | [.eventTime,
          (.userIdentity.accessKeyId // "unknown"),
          (.userIdentity.arn // "unknown"),
          .eventName,
          (.errorCode // "-"),
          (.sourceIPAddress // "-")] | @tsv' \
  "$OUT/events-raw.json" | sort -k2,2 -k1,1 > "$OUT/timeline.tsv"

echo "rows: $(wc -l < "$OUT/timeline.tsv")"

# 4. Freeze the inputs.
( cd "$OUT" && sha256sum ./*.json ./*.tsv > SHA256SUMS )
echo "frozen: $OUT/SHA256SUMS"
```

## Notes That Prevent Wrong Runs

- `lookup-events` caps at the event history and honours `--max-items` as a truncation point, returning a `NextToken` when there is more. A single call is not a complete extraction; loop on the token and record the count.
- `lookup-events` never returns data events. Any object-read question needs an Athena table or an event data store, and a zero from this command must not be reported as no reads.
- `jq fromjson` on `CloudTrailEvent` is required because `lookup-events` nests the record as a string; selecting `.eventName` from the wrapper returns null and quietly empties the timeline.
- Athena charges per byte scanned. Partition on the account and date prefixes rather than scanning the whole trail bucket, and pin the workgroup so query cost and output location are attributable.
- `sort -k2,2 -k1,1` orders by session key then time, which is the reconstruction order. Sorting by time alone merges concurrent sessions and produces a narrative that no single actor performed.
