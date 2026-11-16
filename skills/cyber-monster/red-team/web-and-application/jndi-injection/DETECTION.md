# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jndi-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs showing javax.naming.NamingException or CommunicationException with an attacker-looking PROVIDER_URL.
- Outbound connections from the JVM to ldap:// (389/636), rmi:// (1099), or iiop ports absent from the dependency map.
- DNS resolution of unfamiliar hostnames contained in a request parameter that feeds a naming lookup.
- Config-override or connector-setup events setting Context.PROVIDER_URL from request-derived values.
- JVM stack traces containing com.sun.jndi.ldap.LdapCtxFactory or InitialContext.lookup on a request thread.
- EDR records of the JVM loading classes from a remote codebase URL after a lookup.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
