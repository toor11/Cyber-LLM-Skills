# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cloud-storage-and-metadata-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Storage access log: `requester` equal to `-` (anonymous) on a successful `GET`.
- CDN or proxy log: a signed-URL query string appearing in a `Referer` header to another origin.
- Application log: a presigning call with an expiry above the documented maximum, flagged at review.
- Cloud storage audit: an `AllUsers` or `allAuthenticatedUsers` grant added to a bucket or object.
- Data-classification finding: a bucket tagged as public containing objects whose names match state or backup patterns.
- Egress metric: a volume of anonymous downloads from one ASN that exceeds the baseline for the object class.
- Configuration event: `s3:PutBucketAcl` or `PutBucketPolicy` granting a public principal.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
