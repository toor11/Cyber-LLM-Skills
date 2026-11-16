# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xxe-ooxml-and-svg`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Uploaded office files whose inner word/document.xml or xl/workbook.xml contains a `<!DOCTYPE` declaration.
- SVG uploads whose prolog includes a DOCTYPE or an ENTITY declaration before the svg element.
- Document-ingestion worker logs recording external entity resolution while processing an upload.
- Outbound connections from a thumbnailing or conversion service to an external host after a document upload.
- File-read audit events by a document-processing service account for paths outside the upload store.
- A conversion job error referencing an undefined entity or an external DTD during document parsing.
- Zip members in uploaded documents whose size or content deviates from a benign template baseline.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
