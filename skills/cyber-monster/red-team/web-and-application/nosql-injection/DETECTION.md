# Detection Signals and Blue-Team Handoff

> Sub-skill: [`nosql-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Request bodies where a field expected to be a string arrives as a JSON object containing $ne, $gt, $regex, or $where.
- Query strings with bracketed operator syntax (`password[$ne]=`, `age[$gt]=`) on login or search routes.
- MongoDB server logs showing $where or mapReduce operations on collections that normally use simple finds.
- Login success events where the password field in the upstream request was not a scalar.
- A search route returning a document count far above its historical median after an operator-shaped parameter.
- Repeated requests varying an anchored $regex prefix (^a, ^b), characteristic of blind extraction.
- Application framework warnings about sanitised $-prefixed keys, indicating attempted operator injection.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
