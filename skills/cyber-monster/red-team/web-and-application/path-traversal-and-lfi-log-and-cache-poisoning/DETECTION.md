# Detection Signals and Blue-Team Handoff

> Sub-skill: [`path-traversal-and-lfi-log-and-cache-poisoning`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- access.log entries whose User-Agent or Referer field contains PHP open tags or template delimiters.
- error.log malformed-request entries carrying script tags or control bytes from the request line.
- Mail spool files under /var/mail or /var/spool whose stored envelope fields contain markup.
- File-inclusion routes resolving a path that ends in .log, .eml, or a cache file extension.
- Gaps between a logrotate event and a subsequent include request targeting the prior log generation.
- Cache or opcache file writes whose content derives from a request-controlled key, followed by an include of that file.
- Web-user read access to /var/log or the mail spool immediately before an include route is hit.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) | Detection queries, triage, and hardening for this technique |
