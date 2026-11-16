# Detection Signals and Blue-Team Handoff

> Sub-skill: [`insecure-deserialization-java-gadgets`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF or app logs where a parameter or cookie value base64-decodes to a string beginning rO0AB or raw bytes AC ED 00 05.
- JVM logs showing java.io.InvalidClassException or ClassNotFoundException raised from ObjectInputStream.resolveClass during request handling.
- Outbound DNS lookups from the app JVM to an unfamiliar host immediately after a POST carrying a serialized blob (URLDNS signature).
- APM stack traces containing readObject frames from org.apache.commons.collections, org.apache.commons.beanutils, or org.codehaus.groovy on user requests.
- Child processes such as cmd.exe or /bin/sh spawned by the Java application PID with no corresponding business workflow.
- RASP or SecurityManager alerts for reflective Runtime.exec or TemplatesImpl.newTransformer under a deserialization call stack.
- Network egress from the app tier to LDAP (389/636) or the RMI registry (1099) not present in the service dependency map.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) | Detection queries, triage, and hardening for this technique |
