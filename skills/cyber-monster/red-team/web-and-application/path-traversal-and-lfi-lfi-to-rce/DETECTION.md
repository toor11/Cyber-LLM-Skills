# Detection Signals and Blue-Team Handoff

> Sub-skill: [`path-traversal-and-lfi-lfi-to-rce`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access logs where a single view, page, or file parameter value contains ../, /var/log/, /proc/self/, or php:// within one session.
- PHP-FPM or Apache error_log entries showing include() or require() with a resolved path under /var/log, /tmp, or /var/lib/php/sessions.
- File integrity events on /var/lib/php/sessions where a session file's contents include markup or PHP open tags from request fields.
- access.log or error.log lines whose User-Agent or Referer field carries PHP open tags, followed by a request that includes that same log path.
- auditd EXECVE events or PHP child processes spawned by the web user immediately after a request to a file-inclusion route.
- Response-size anomalies on an include route where the body length matches a known system file rather than a template.
- Requests to pearcmd.php or /proc/self/environ from the web tier that have no legitimate application dependency.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) | Detection queries, triage, and hardening for this technique |
