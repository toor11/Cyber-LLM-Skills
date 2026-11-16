# Detection Signals and Blue-Team Handoff

> Sub-skill: [`type-juggling-and-loose-comparison-php-juggling`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- PHP error-log entries for a strcmp argument type error naming an array near an auth handler.
- Access logs with `pw[]=` or other array parameters on login endpoints.
- Static analysis flagging loose equality, `strcmp(...) == 0`, or non-strict `in_array` in PHP auth paths.
- Successful authentications where the submitted credential equals a known magic-hash string such as `QNKCDZO` or `240610708`.
- PHP array-to-string conversion notices correlated with authentication requests.
- Repeated POSTs cycling `0e`-prefixed values against a token or password field.
- WAF rules matching array-type parameters on endpoints documented to accept scalars.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
