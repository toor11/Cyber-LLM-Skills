# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssrf-cloud-metadata`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- VPC flow logs showing the application ENI connecting to 169.254.169.254.
- Outbound requests carrying X-aws-ec2-metadata-token, Metadata-Flavor, or Metadata headers that originate from a request handler.
- CloudTrail or provider logs showing instance-role credentials used from an IP outside the instance.
- Access to the iam/security-credentials path in application or proxy logs.
- url parameters resolving to 169.254.169.254, metadata.google.internal, or the Azure IMDS address.
- IMDS request counts rising on an instance whose workload does not normally read metadata.
- Webhook or import endpoints forwarding caller-supplied headers to outbound fetches.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Detection queries, triage, and hardening for this technique |
