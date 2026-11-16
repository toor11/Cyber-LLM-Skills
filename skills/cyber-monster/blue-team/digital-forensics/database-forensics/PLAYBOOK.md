# Operational Triage and Response Playbook

> Sub-skill: [`database-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `database-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Database evidence is destroyed by the most ordinary administrative actions: stopping a service cleanly checkpoints and deletes the WAL, starting it replays and rewrites logs, and a "quick backup" with a logical dump drops the remnants that deletion recovery depends on. The runbook therefore treats the data directory as a crime scene with a very short preservation window, and it insists on recording the engine's configuration before any interpretation: what is recoverable is a function of `secure_delete`, `binlog_row_image`, `wal_level` and archive mode, not of how hard you look.

## Triggers

- Alert, hunt outlier, or review request matching `database forensics`.
- Alert, hunt outlier, or review request matching `transaction log analysis`.
- Alert, hunt outlier, or review request matching `db audit`.
- A bulk export, unexpected `DROP`/`TRUNCATE`, or a row count that changes outside a deployment window.
- A data-integrity complaint where the question is whether a row was altered or removed, and by which session.
- An engine audit log stops recording for a window in which the application kept writing.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Binlog row events show deletes outside any application traffic window, with a matching session record | Confirmed data destruction | Preserve binlogs and the engine audit range with digests; scope which credential owned the session |
| Recovery yields rows absent from the live table while `secure_delete=OFF` | Confirmed deletion, partial attribution | Report as recovered content; corroborate with a session record before asserting a time or an actor |
| WAL or binlog checkpointed and deleted on clean shutdown before capture | Inconclusive (Evidence Lost) | Filesystem snapshot and OS-level write records only; state the loss explicitly |
| Audit logging was disabled for the whole window | Inconclusive (Telemetry Gap) | Do NOT close as clean; open a control action to enable engine-level auditing |
| `VACUUM` or `OPTIMIZE TABLE` in the engine log during the window | Benign Baseline (maintenance) | Record the maintenance window and its owner; remove the affected remnants from the evidence basis |
| Log position or timeline resets with a promotion record in the server log | Benign Baseline (failover) | Re-baseline the sequence against the new primary; no tampering finding |
| Data files changed with no matching engine transaction and no maintenance record | Confirmed tampering (file-level) | Preserve the files and the OS write evidence; treat the database's own consistency as untrusted |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot the volume or data directory, copy every sidecar and archived log, and record SHA-256 for each. Do not stop the service as a first step — a clean stop checkpoints the WAL and removes the newest evidence; capture the files first, then coordinate the stop with the application owner.
2. **Never run the engine against the original files.** Restore to a copy, start there, and analyse there. Starting the original replays logs and rewrites the very artifacts the investigation needs.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and for databases, never fail over, restart or reconfigure replication on a production cluster without the application owner's explicit agreement.
4. **Rotate credentials that had write access:** a session that deleted rows was authenticated as some principal, and that principal's secret may be held by more than one client. Rotate, then re-derive which other systems used the same credential.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the vector was an over-privileged application account, fix the grants and enable engine-level auditing so the next incident is attributable, rather than adding logging after the fact on one host.
