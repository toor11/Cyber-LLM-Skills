# Detection Signals and Blue-Team Handoff

> Sub-skill: [`file-upload-and-webshell-filename-and-path-abuse`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Upload multipart `filename` fields containing `../`, `..\\`, encoded traversal, or absolute paths.
- File-integrity events creating or modifying files outside the designated upload directory after an upload request.
- Overwrite events on existing files in shared or system directories correlated with an upload POST.
- Access logs requesting sequential or predictable upload paths not linked to a prior listing.
- Application logs where the stored path differs from the configured upload root.
- Duplicate-name upload bursts targeting one destination, consistent with overwrite or race attempts.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) | Detection queries, triage, and hardening for this technique |
