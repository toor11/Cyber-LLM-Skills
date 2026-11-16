# Detection Signals and Blue-Team Handoff

> Sub-skill: [`file-upload-and-webshell-polyglot-and-archive`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Archive-extraction logs writing member paths that resolve outside the extraction directory.
- Extraction of members flagged as symlinks or carrying absolute paths.
- Uploaded images that pass a type check but fail to re-decode cleanly as that image.
- SVG or OOXML uploads stored in a directory later rendered in the application origin.
- File-integrity creation of files outside the extraction root timed with an archive import.
- Document-parser errors referencing external entities or script elements in uploaded files.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) | Detection queries, triage, and hardening for this technique |
