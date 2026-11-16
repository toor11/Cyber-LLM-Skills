# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cloud-recon-and-enumeration`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: a burst of `Describe` or `List` calls from one principal across services it has never used.
- CloudTrail field: `errorCode: AccessDenied` followed by a different resource class being enumerated, which is the boundary probe pattern.
- S3 server access log: a sequence of `REST.HEAD.OBJECT` or bucket-level requests from one source spanning many candidate names.
- DNS query log: a burst of NXDOMAIN for subdomains of one zone from a single resolver, which is the subdomain enumeration shape.
- Cloudflare or CDN log: 404 responses distributed across many host paths with uniform timing, which is the existence probe.
- GuardDuty finding: `Recon:IAMUser/ResourcePermissions` or `Discovery:S3/BucketEnumeration`.
- Certificate transparency monitor: a new certificate for an internal name, which is the reverse direction of the same channel.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
