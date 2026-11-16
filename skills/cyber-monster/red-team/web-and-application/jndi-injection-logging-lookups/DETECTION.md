# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jndi-injection-logging-lookups`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Reverse-proxy and app logs where User-Agent, X-Forwarded-For, or any logged header contains ${jndi: or ${lower:/${upper: sequences.
- Log4j or Logback internal errors referencing JndiLookup or an error looking up a JNDI resource.
- Outbound LDAP, RMI, or DNS callbacks from the JVM correlated within milliseconds of a request whose header was logged.
- Presence of JndiLookup.class in loaded log4j-core jars on affected 2.x versions, from an inventory scan.
- SIEM matches for nested-expression obfuscation such as ${${lower:j}ndi in any indexed log field.
- JVM egress to port 1389 or 389 immediately after an error-path log write.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
