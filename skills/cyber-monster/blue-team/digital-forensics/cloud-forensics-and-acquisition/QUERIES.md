# Artifacts and Queries

> Sub-skill: [`cloud-forensics-and-acquisition`](SKILL.md) | Family: **Digital Forensics**

Acquisition and evidence-extraction commands owned by `cloud-forensics-and-acquisition`. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Everything here is read-only or snapshot-only: no command detaches, terminates, resizes or changes policy on a source resource. Confirm the subcommand surface with `aws <service> help` on the installed CLI version.

## Class 1 — Coverage and integrity gate (run before any other class)

Expected hit: a trail that is multi-Region, logging, validating, with data events configured for the buckets in scope; and digest validation passing across the export range. A trail without validation, or a validation failure, caps what any later class can prove.

```bash
aws cloudtrail describe-trails --include-shadow-trails --region "$REGION" \
  --query 'trailList[].{Name:Name,MultiRegion:IsMultiRegionTrail,LogValidation:LogFileValidationEnabled,S3:S3BucketName,Kms:KmsKeyId}' \
  --output table

aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" \
  --query 'EventSelectors[].{Read:ReadWriteType,Data:DataResources[].Type}' --output json

aws cloudtrail validate-logs --trail-name "$TRAIL" --region "$REGION" \
  --start-time "$START" --end-time "$END"
```

False-positive note: a trail that exists but has `IsMultiRegionTrail: false` records only its home Region, so an empty result for another Region means "not recorded there", never "nothing happened there". Shadow trails created by other accounts or by Control Tower appear in the listing and must not be read as your own coverage.

## Class 2 — Snapshot and volume acquisition

Expected hit: one snapshot per attached volume, encrypted with the account's key, tagged with the case identifier, and shared only to the forensics account. Record the snapshot ID, source volume and creation time.

```bash
VOLS=$(aws ec2 describe-volumes --region "$REGION" \
  --filters Name=attachment.instance-id,Values="$INSTANCE_ID" \
  --query 'Volumes[].VolumeId' --output text)

for v in $VOLS; do
  aws ec2 create-snapshot --region "$REGION" --volume-id "$v" \
    --description "case=$CASE host=$INSTANCE_ID vol=$v" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=case,Value=$CASE}]" \
    --query 'SnapshotId' --output text
done

aws ec2 describe-snapshots --region "$REGION" --owner-ids self \
  --filters Name=tag:case,Values="$CASE" \
  --query 'Snapshots[].{Id:SnapshotId,Vol:VolumeId,Start:StartTime,Enc:Encrypted,State:State}' \
  --output table
```

False-positive note: `State: pending` snapshots are not yet readable and restoring one too early produces a truncated volume that looks like a wiped disk. Also expect `Encrypted: false` on volumes created from a public or shared AMI; that is a default, not tampering, unless sibling volumes are encrypted.

## Class 3 — Control-plane timeline (who did what)

Expected hit: a bounded export of management events with principal, source IP, user agent and error code preserved. An unbounded lookup is not a timeline and cannot be reviewed.

```bash
aws cloudtrail lookup-events --region "$REGION" \
  --start-time "$START" --end-time "$END" --max-results 50 \
  --output json > "ct-$REGION.json"
sha256sum "ct-$REGION.json" | tee -a evidence-manifest.txt

jq -r '.Events[].CloudTrailEvent | fromjson
  | select(.readOnly == false)
  | [.eventTime, .eventSource, .eventName, .userIdentity.arn,
     .sourceIPAddress, .userAgent, (.errorCode // "-")] | @tsv' \
  "ct-$REGION.json" | sort | uniq -c | sort -rn | head -50
```

False-positive note: `lookup-events` reads event history only, which holds 90 days of management events per Region and excludes read-only events in the console default view. An export that omits `readOnly: false` filtering still misses data events entirely — they are not in event history at all.

## Class 4 — Object access and flow evidence

Expected hit: S3 server access log lines or CloudTrail data events for the objects in scope, and VPC flow records for the network paths those objects were read across. Absence in one source with presence in the other localises which control was off.

```bash
# Data events, if enabled for the bucket.
aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$BUCKET" \
  --start-time "$START" --end-time "$END" --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | [.eventTime, .eventName, .userIdentity.arn, .sourceIPAddress,
         .requestParameters.key, (.errorCode // "OK")] | @tsv'

# Flow logs for the instance's interface over the same window.
aws logs filter-log-events --region "$REGION" \
  --log-group-name "/vpc/flowlogs/$VPC" \
  --start-time "$(date -d "$START" +%s000)" --end-time "$(date -d "$END" +%s000)" \
  --filter-pattern '[version, account, eni, src, dst, srcport, dstport, proto, packets, bytes, start, end, action="REJECT", flowlogstatus]'
```

False-positive note: S3 server access logs are delivered best-effort, so a missing line is not proof a request did not happen; and the VPC filter above requires the flow log format to actually contain those fields in that order. Check the log format before trusting a filter pattern.

## Class 5 — Identity and credential evidence

Expected hit: the specific credential's use, bounded by time and correlated to the principal that owns it. A leaked access key's history is the finding; a high total call count for a service role is not.

```bash
aws iam get-credential-report --output text --query Content | base64 -d > creds.csv
awk -F, 'NR==1 || $1=="<ACCESS_KEY_ID>"' creds.csv

aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" --end-time "$END" \
  --query 'Events[].CloudTrailEvent' --output text \
  | jq -R 'fromjson? | [.eventTime, .eventName, .sourceIPAddress, .userAgent] | @tsv' \
  | sort | head -40
```

False-positive note: deactivating a leaked key is urgent, but deleting it removes it from the credential report before you have recorded it. Deactivate, record, then delete later — and note that an access key used by an assumed role appears under the role's identity, not the key's.

## Class 6 — Retention tier check

Expected hit: a statement of which tier holds the window you need. A negative result from a lake-tier query proves only that the lake lacks the data, not that the event did not occur.

```bash
aws logs describe-log-groups --region "$REGION" \
  --query 'logGroups[].{Name:logGroupName,Retention:retentionInDays,Stored:storedBytes}' \
  --output table
aws s3api get-object-lock-configuration --bucket "$EVIDENCE_BUCKET" --region "$REGION"
aws s3api get-bucket-versioning --bucket "$EVIDENCE_BUCKET" --region "$REGION"
```

False-positive note: `retentionInDays` absent means "never expire", not "unlimited history" — the group may still have been created recently. Object Lock in governance mode can be bypassed by a principal with the right permission, so read the mode and the bypass governance retention setting before calling an object immutable.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, beside every cloud finding, the Region set, the tier consulted and the integrity state of the log chain; an absence claim without those three is not reviewable.
