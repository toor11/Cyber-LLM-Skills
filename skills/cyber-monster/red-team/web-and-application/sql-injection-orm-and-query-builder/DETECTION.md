# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-orm-and-query-builder`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where an ORDER BY or column parameter carries a value absent from the model field list.
- ORM debug or query logs showing `extra`, `RawSQL`, `whereRaw`, or `queryRawUnsafe` statements whose text contains request-derived quotes.
- Database parse or unknown-column error events correlated with a request parameter used as a sort or filter token.
- Repeated requests from one session alternating a sort parameter between a valid column and a syntactically odd token within seconds.
- APM spans for one endpoint whose generated SQL varies in structure across requests on the same route.
- Code-scanning findings that tie a tainted HTTP parameter to a raw-fragment builder sink.
- Row counts from an endpoint that normally returns a bounded page spiking, indicating a tautology fragment.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
