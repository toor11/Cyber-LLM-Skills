# Detection Signals and Blue-Team Handoff

> Sub-skill: [`serverless-and-function-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Lambda invocation metric: `UrlRequest` count on a function URL with `AuthType: NONE`, which is the direct exposure measure.
- CloudTrail data event: `lambda:InvokeFunctionUrl` from an unauthenticated or unexpected principal.
- Configuration audit: a function created with `Environment.Variables` keys matching a secret-name pattern.
- IAM Access Analyzer: an execution role with unused permissions, which shows the role is broader than the function's behaviour.
- Cost anomaly: a spike in invocations or GB-seconds on one function, which is the resource-abuse signal.
- CloudTrail event: `lambda:GetFunctionConfiguration` from a principal that does not deploy functions, which reads the environment.
- Configuration event: a function URL created or its `AuthType` changed to `NONE`.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
