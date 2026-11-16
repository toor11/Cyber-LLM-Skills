# Detection Signals and Blue-Team Handoff

> Sub-skill: [`insecure-deserialization-php-gadgets`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- App or WAF logs where a cookie or POST field matches the shape O:<digits>:" indicating a serialized PHP object.
- PHP error logs showing __wakeup or __destruct exceptions or an unserialize(): Error at offset entry during request handling.
- File-access events opening a phar:// stream wrapper from a user-supplied path parameter.
- auditd or EDR records of php-fpm spawning sh, bash, or curl without a matching application code path.
- Web-server logs for uploads whose content begins with PK or GIF magic but carry a .phar or image extension later read by a metadata function.
- Outbound connections from the php-fpm worker to unexpected hosts shortly after a request carrying an object string.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) | Detection queries, triage, and hardening for this technique |
