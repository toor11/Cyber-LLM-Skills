# Detection Signals and Blue-Team Handoff

> Sub-skill: [`path-traversal-and-lfi-php-wrappers`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Request parameters containing php://, data://, phar://, expect://, or zip:// scheme prefixes.
- access.log entries where a doc or file parameter base64-encodes the name of a known source file.
- PHP error_log warnings referencing phar unserialize or __wakeup during a file operation.
- Parameters carrying convert.iconv or convert.base64-encode substrings on a file-reading route.
- File operations opening phar: paths that the application code never legitimately references.
- phpinfo or configuration exposure showing allow_url_include enabled on an internet-facing host.
- Uploads of .phar or .zip artefacts followed by requests that reference them through a stream wrapper.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) | Detection queries, triage, and hardening for this technique |
