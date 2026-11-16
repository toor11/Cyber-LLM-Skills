# Detection Signals and Blue-Team Handoff

> Sub-skill: [`type-juggling-and-loose-comparison`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authentication logs where a login succeeds with a token value matching a `0e`-followed-by-digits magic-hash pattern.
- Application logs showing array-typed parameters such as `param[]=` on fields expected to be scalar.
- Code-scan findings for loose equality, non-strict membership tests, or switch on user input in auth paths.
- WAF events where a password or token field carries values like `240610708` or `QNKCDZO`.
- Repeated login attempts from one session cycling short numeric strings against a token field.
- Framework warnings about type coercion or an array-to-string conversion near a comparison.
- Successful privilege checks where the request body sent a JSON boolean for a field normally a string.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
