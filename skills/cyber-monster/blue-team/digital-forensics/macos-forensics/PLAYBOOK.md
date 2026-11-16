# Operational Triage and Response Playbook

> Sub-skill: [`macos-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `macos-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

macOS evidence is short-lived and permission-gated: the unified log rolls on a managed schedule, several databases require Full Disk Access even for an administrator, and APFS snapshots quietly hold the pre-incident state that the live volume no longer shows. The runbook's first move is therefore always collection — a log archive and a snapshot inventory — before any analytical query, because the analytical queries are cheap to redo and the records are not.

## Triggers

- Alert, hunt outlier, or review request matching `macos forensics`.
- Alert, hunt outlier, or review request matching `unified log`.
- Alert, hunt outlier, or review request matching `fsevents`.
- Alert, hunt outlier, or review request matching `launchd forensics`.
- An EDR or MDM alert names a Mac, and the question is what executed and what persisted.
- A user reports a privacy prompt they did not approve, or an application behaves as if it has permissions it should not.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Quarantine row plus a filesystem creation time and a launchd item for the same bundle | Confirmed delivery and persistence | Archive the log, copy the databases, and scope the agent's `ProgramArguments` target |
| TCC grant with `last_modified` and no matching consent prompt, no PPPC profile | Confirmed anomalous grant | Preserve both TCC databases and the log window; check what the granted client can reach |
| Unified log's oldest visible entry is after the suspected window | Inconclusive (Retention Gap) | Pivot to FSEvents, knowledgeC and APFS snapshots; state the retention limit in the report |
| FSEvents shows the path change but no timed source covers the period | Partial (Order only) | Report order without a clock, or anchor to an external source and name it |
| Launch agent present but owned by a package receipt and hash-matching | Benign Baseline (installed) | Record the receipt; remove it from the candidate set |
| Suspect binary is x86-64 on Apple silicon with Rosetta 2 translation entries in the log | Confirmed execution path | Preserve the translation log window; note that the AOT cache may already be evicted |
| SQLite sidecars absent and recent rows unrecoverable | Inconclusive (Partial Database) | Check APFS snapshots for an earlier copy of the database with its sidecars intact |

## Containment and Recovery

1. **Preserve before mutating:** run `log collect` for the window, copy the TCC, quarantine and knowledgeC databases with sidecars, and inventory APFS snapshots — all before any reboot, profile change or app removal. Removing a malicious launch agent destroys the record of its configuration.
2. **Capture the snapshot, not just the live volume.** APFS local snapshots frequently hold a copy of the databases and logs from before the incident, and they are the only route back when the live store has rolled.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and on macOS, do not disable SIP, remove configuration profiles or wipe a device under investigation, since each closes a recovery route permanently.
4. **Scope by identity and grant:** an anomalous TCC grant means the client could read mail, contacts, screen or files. Enumerate what the grant covers and check the identity provider's sign-in log for the account on that device.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the vector was an unmanaged app install or a missing PPPC restriction, fix it by profile so the next device is covered before the user logs in.
