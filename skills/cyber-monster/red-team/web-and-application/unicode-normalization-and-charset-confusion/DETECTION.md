# Detection Signals and Blue-Team Handoff

> Sub-skill: [`unicode-normalization-and-charset-confusion`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Logs where a stored username or email differs in code points from its normalized form, indicating a collision.
- Database unique-constraint violations or duplicate-key errors on identifiers that look distinct.
- WAF events where a rule matched the normalized body but not the raw body or the reverse.
- Application logs showing `unicodedata.normalize`, Java `Normalizer.normalize`, or ICU calls after a validation step.
- Requests containing non-ASCII code points in fields constrained to ASCII identifiers such as hostnames or usernames.
- Jackson or JSON parser warnings about numeric or hex coercion on string fields.
- Account-takeover reports where two users resolve to one canonical identity at the authentication store.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
