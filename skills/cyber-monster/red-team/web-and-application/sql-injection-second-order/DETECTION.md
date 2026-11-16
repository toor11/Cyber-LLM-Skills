# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-second-order`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Database queries whose literal text contains values that match stored user profile fields rather than request parameters.
- Errors such as 1064 or 42601 raised by batch jobs or admin screens rather than by the endpoint that received the input.
- Audit logs where an account-recovery or password-change query references a username containing quote characters.
- A stored field value appearing verbatim inside a different endpoint generated SQL in query logs.
- Latency anomalies on scheduled jobs that correlate with recently created or edited records.
- Admin-panel render events immediately followed by database parse errors on the same row id.
- Write endpoints accepting fields with unescaped quotes that later feed reporting pipelines.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
