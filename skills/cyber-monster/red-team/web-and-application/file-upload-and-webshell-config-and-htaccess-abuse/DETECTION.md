# Detection Signals and Blue-Team Handoff

> Sub-skill: [`file-upload-and-webshell-config-and-htaccess-abuse`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Upload directories receiving files literally named `.htaccess`, `.user.ini`, or `web.config`.
- Apache access or error logs showing `AddType` or `AddHandler` taking effect for files in an upload path.
- IIS logs where a `web.config` under an upload directory registers a handler or enables server-side includes.
- PHP-FPM logs referencing a `.user.ini` with `auto_prepend_file` under a user-writable directory.
- A content file in the upload directory served first as a static MIME then later as a dynamic type.
- File-integrity creation events for configuration filenames in directories meant to hold media.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) | Detection queries, triage, and hardening for this technique |
