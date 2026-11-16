# Detection Signals and Blue-Team Handoff

> Sub-skill: [`steganography-and-covert-channels`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Object-store field: stored size minus decoded pixel size for images, which is the appended-region metric.
- Metadata signal: count of non-empty comment and user-comment fields per upload, alerted on high-entropy values.
- Text-field metric: format-character count per submitted comment or name, alerted on runs rather than single occurrences.
- Egress metric: download `Content-Length` exceeding the indexed artefact size.
- Pipeline event: an upload path that lacks a decode-and-re-encode step, identified from the handler's code rather than traffic.
- Content-type signal: declared type accepted while the decoded format differs, from the validator's own log.
- Archive audit: an object written with a size delta over its previous version while its content hash is unchanged.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
