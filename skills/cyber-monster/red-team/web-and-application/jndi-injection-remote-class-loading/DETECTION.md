# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jndi-injection-remote-class-loading`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- JVM class-loading events fetching bytecode over http or https from a host named in an LDAP or RMI Reference.
- System property or startup flag com.sun.jndi.ldap.object.trustURLCodebase or the rmi equivalent set to true.
- Outbound RMI (1099) or LDAP (389) connections followed by an HTTP GET for a .class file from the same host.
- APM traces showing ObjectFactory.getObjectInstance or BeanFactory instantiation from a lookup result.
- EDR alerts for the JVM writing and loading a transient class file under a temp directory during request handling.
- Loaded-class inventory revealing attacker-named factory classes not shipped with the application.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
