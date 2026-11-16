# Detection Signals and Blue-Team Handoff

> Sub-skill: [`aws-attacks-s3-and-storage`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- S3 server access log field: `requester` equal to `-` (anonymous) on a `REST.GET.OBJECT` record, which is the direct public-read signal.
- CloudTrail data event: `s3:GetObject` from a principal ARN outside the organisation, on an object class that should be internal.
- Macie finding: sensitive data in a bucket with a public or cross-account grant.
- Access Analyzer finding: a bucket policy granting access to a principal outside the zone of trust.
- Configuration event: `s3:PutBucketPublicAccessBlock` with any flag set to `false`, which reopens a path.
- CloudTrail event: `s3:PutBucketPolicy` outside a change window, reviewed against the approved policy set.
- Encryption audit field: a bucket with no default encryption, or SSE-S3 where the data classification requires SSE-KMS.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
