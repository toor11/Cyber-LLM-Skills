# Detection Signals and Blue-Team Handoff

> Sub-skill: [`aws-attacks-compute-and-metadata`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- VPC flow log: traffic to `169.254.169.254` from a source that is not the instance's own agent, especially from a container CIDR.
- CloudTrail event: `ec2:DescribeInstanceAttribute` calls that return `userData`, which is how the secret is read without touching the endpoint.
- CloudTrail event: `ec2:ModifyInstanceMetadataOptions` with `httpTokens: optional`, which reopens v1.
- GuardDuty finding: `UnauthorizedAccess:EC2/MetadataDNSRebind` or `CredentialAccess:IAMUser/InstanceCredentialExfiltration`.
- Application log: an outbound HTTP request to a link-local address from application code, which is the SSRF path being exercised.
- Configuration drift: a launch template whose `http_tokens` differs from the organisational baseline.
- Lambda audit: `lambda:GetFunctionConfiguration` from a principal that does not deploy functions.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
