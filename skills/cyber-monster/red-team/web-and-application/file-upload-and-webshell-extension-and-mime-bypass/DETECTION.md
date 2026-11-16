# Detection Signals and Blue-Team Handoff

> Sub-skill: [`file-upload-and-webshell-extension-and-mime-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Upload bodies whose magic-byte prefix (`\x89PNG`, `GIF89a`, `%PDF`) does not match the declared `Content-Type`.
- Stored filenames carrying double extensions or executable suffixes (`.phtml`, `.phar`) in media upload directories.
- WAF multipart inspection flagging script tokens inside a declared image part.
- Access logs fetching a just-uploaded file whose response content type is dynamic rather than the stored image MIME.
- Repeated uploads from one session cycling filename-suffix and Content-Type variants, characteristic of extension fuzzing.
- Image-processing pipeline logs where a file accepted as an image fails to decode as one.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) | Detection queries, triage, and hardening for this technique |
