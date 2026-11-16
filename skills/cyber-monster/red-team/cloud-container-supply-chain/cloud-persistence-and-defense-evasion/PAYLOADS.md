# Verification Probes and Expected Differentials

> Sub-skill: [`cloud-persistence-and-defense-evasion`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Credential and trust inventory

```text
# Access keys per user, with creation dates.
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read -r u; do
  aws iam list-access-keys --user-name "$u" --query "AccessKeyMetadata[].{user:UserName,id:AccessKeyId,created:CreateDate}" --output json
done | jq -s 'add | map(select(. != null))'
# Trust policies that name a wildcard or a root principal.
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json \  # cloud-persistence-and-defense-evasion: class 1 credential and
  | jq -r '.[] | select((.[1].Statement[]?.Principal|tostring)|test("\\*|:root")) | .[0]'  # cloud-persistence-and-defense-evasion: class 1 credential and
```

Expected differential: one key per user with a creation date that matches the rotation log is the control; a second key with no matching record is the persistence.

## Class 2 — Scheduled compute inventory

```text
aws events list-rules --query 'Rules[].{name:Name,schedule:ScheduleExpression,state:State}' --output table
aws lambda list-functions --query 'Functions[].{name:FunctionName,modified:LastModified,runtime:Runtime}' --output table
```

Expected differential: a rule and a function that both appear in the IaC state are explained; a function whose name matches no state entry, invoked by a schedule, is the persistence.

## Class 3 — Logging-integrity audit

```text
aws cloudtrail describe-trails --query 'trailList[].{name:Name,multi:IsMultiRegionTrail,org:IsOrganizationTrail,bucket:S3BucketName}' --output table
aws cloudtrail get-trail-status --name "$TRAIL" --query '{logging:IsLogging,latest:LatestDeliveryTime}'
aws guardduty list-detectors --query 'DetectorIds' --output text
```

Expected differential: a multi-Region organisation trail with logging on and a detector in every Region is the control; a single-Region trail, an excluded account, or a disabled detector is the evasion surface.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
