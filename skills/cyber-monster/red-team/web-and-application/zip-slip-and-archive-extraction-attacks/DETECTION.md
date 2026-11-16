# Detection Signals and Blue-Team Handoff

> Sub-skill: [`zip-slip-and-archive-extraction-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where an extraction routine writes a file whose resolved absolute path is outside the configured extraction root directory.
- Filesystem audit events (Linux auditd `PATH` records, Windows Event ID 4663) showing the unpack process creating files above its destination argument.
- Archive-processing worker logs recording an entry name containing `../`, a leading `/`, or a `\\` UNC prefix at extract time.
- Symlink or hardlink creation by the extraction service process in EDR file-operation telemetry, immediately followed by a write through that link.
- A spike in the ratio of bytes written to archive bytes read for a single upload, indicating a decompression-amplification attempt (CWE-409).
- Web server access logs showing a newly written script or executable served from the extraction directory shortly after an archive upload.
- Process telemetry where the extractor opens or writes files under `/etc`, `~/.ssh`, or a web root that are not descendants of its destination path.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
