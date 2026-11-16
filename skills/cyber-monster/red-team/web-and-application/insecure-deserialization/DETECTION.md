# Detection Signals and Blue-Team Handoff

> Sub-skill: [`insecure-deserialization`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where a request field decodes to a Java object stream (`rO0AB` or `AC ED 00 05`) on a route expecting plain data.
- Deserialization exceptions (`InvalidClassException`, `ClassNotFoundException`, pickle `UnpicklingError`) tied to request-sourced input.
- Runtime events where a deserializer instantiated a type outside the application's normal object set.
- Child processes spawned by the application runtime shortly after a request carrying a serialized token.
- Kafka Connect connector configuration changes that set a JAAS login module with a deserialization callback.
- Access to management or license servlets (GoAnywhere class) with serialized payloads from unauthenticated sources.
- Outbound JNDI, LDAP, or RMI connections from the app runtime immediately after a deserialization call.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) | Detection queries, triage, and hardening for this technique |
