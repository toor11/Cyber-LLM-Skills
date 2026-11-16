# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cloud-incident-response`](SKILL.md) | Family: **Incident Response**

Verified read-and-attest entry points for a cloud incident. Every command below is a describe, list or get call: it records state before anyone changes it. Never invent flags — `aws` subcommands add options between CLI majors, and `az` renamed several `show`-family arguments in recent versions, so confirm with `<cmd> --help` on the installed build.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| AWS CLI | `aws cloudtrail describe-trails --include-shadow-trails --query "trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled,S3BucketName]" --output table` | Prove trail scope, validation and destination ownership before trusting any event query | Any host with AWS credentials |
| AWS CLI | `aws cloudtrail get-trail-status --name <trail> --query "{Logging:IsLogging,Latest:LatestDeliveryTime}"` | Confirm logging is currently on and when the last delivery landed; a stale `LatestDeliveryTime` is a silent gap | Any host with AWS credentials |
| AWS CLI | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --start-time <iso> --max-items 50` | Management-event lookup that works within the ninety-day event history without Athena | Any host with AWS credentials |
| AWS CLI | `aws iam get-role --role-name <role> --query "Role.AssumeRolePolicyDocument"` | Inspect the trust policy for cross-account or federated paths that survive key rotation | Any host with AWS credentials |
| AWS CLI | `aws ec2 describe-snapshots --owner-ids self --filters "Name=status,Values=completed" --query "Snapshots[].[SnapshotId,StartTime,VolumeSize]"` | Enumerate completed preservation copies as opposed to in-progress ones | Any host with AWS credentials |
| Azure CLI | `az monitor activity-log list --start-time <iso> --offset 7d --query "[?contains(operationName.value,'delete')].[eventTimestamp,operationName.value,caller]" -o table` | Subscription control-plane activity for the window, with the calling principal | Any host with Azure credentials |
| gcloud CLI | `gcloud logging read 'logName:"cloudaudit.googleapis.com"' --freshness=7d --limit=200 --format=json` | Admin Activity and Data Access audit entries across projects | Any host with gcloud credentials |

## Minimal Script Shape

The shape below answers "can I trust this account's audit record at all, and did the actor touch logging" using only describe and lookup calls. It refuses to proceed when logging has never been on.

```bash
#!/usr/bin/env bash
# cloud-log-attest.sh - read-only. Proves trail coverage, then looks for visibility reduction.
set -euo pipefail

TRAIL="${TRAIL:?set TRAIL to the trail name under review}"
REGION="${AWS_REGION:?set AWS_REGION}"
START="${START_ISO:?ISO8601 start of the incident window}"

echo "== 1. trail scope, validation and destination owner =="
aws cloudtrail describe-trails --region "$REGION" --include-shadow-trails \
  --query "trailList[?Name=='${TRAIL}'].[Name,IsMultiRegionTrail,LogFileValidationEnabled,S3BucketName,HomeRegion]" \
  --output table

echo "== 2. current logging state and last delivery =="
status=$(aws cloudtrail get-trail-status --region "$REGION" --name "$TRAIL" \
  --query "{Logging:IsLogging,Latest:LatestDeliveryTime}" --output json)
echo "$status"
if ! grep -q '"Logging": true' <<<"$status"; then
  echo "GAP: trail is not logging - later event queries describe an absence, not innocence"
fi

echo "== 3. any logging-stop or trail-delete inside the window =="
for ev in StopLogging DeleteTrail UpdateTrail; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes "AttributeKey=EventName,AttributeValue=${ev}" \
    --start-time "$START" --max-items 50 \
    --query "Events[].[EventTime,Username,Resources[0].ResourceName]" --output table
done

echo "== 4. snapshot preservation copies that actually completed =="
aws ec2 describe-snapshots --owner-ids self --region "$REGION" \
  --filters "Name=status,Values=completed" \
  --query "Snapshots[].[SnapshotId,StartTime,VolumeSize,Encrypted]" --output table
```

## Notes That Prevent Wrong Runs

- `lookup-events` reads CloudTrail event history, which holds ninety days of management events only. It never returns data events, and a zero result there says nothing about object reads.
- `describe-trails` without `--include-shadow-trails` omits trails created in other regions that still apply; a "single trail" finding from the short list is frequently wrong in multi-region estates.
- `IsMultiRegionTrail: true` does not mean every region is covered — a trail can be multi-region and still exclude a new region until it is re-saved. Confirm with `get-trail` and the region list.
- Snapshot `status: completed` proves the copy exists. It does not prove the responder can read it: check the KMS key policy and whether the key was scheduled for deletion, which breaks decryptability independently of the snapshot.
- Azure Activity Log retains ninety days by default unless exported; any query reaching past that boundary needs the diagnostic-setting export, not the portal blade.
