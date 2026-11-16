# Detection Signals and Blue-Team Handoff

> Sub-skill: [`email-header-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application mail logs where a header-bound field value contains `%0a`, `%0d`, or raw CR/LF characters.
- Sent-message archives showing unexpected `Bcc`, `Cc`, or `Content-Type` headers added to transactional mail from one form.
- MTA logs recording duplicate or malformed header lines on messages from the application's sending identity.
- SMTP conversation logs with ambiguous end-of-data sequences (CRLF-dot variants) between relays.
- Outbound mail volume spikes to recipients not present in the application's intended distribution.
- Web request logs where a contact or invite parameter carries encoded-word or Unicode line-separator sequences.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
