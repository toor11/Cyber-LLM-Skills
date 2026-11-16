---
name: database-forensics
description: "Investigates database evidence: transaction log analysis, deleted row recovery, access auditing and integrity verification. Use when the evidence source is a database."
family: digital-forensics
tier: leaf
triggers: ["database forensics", "transaction log analysis", "db audit"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Database Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Every database keeps two kinds of record, and they fail differently. The data files hold current state and — depending on the engine — recoverable remnants of prior state; the transactional and audit streams hold the sequence of changes. SQLite, the engine behind most browsers, embedded applications and mobile apps, writes changes into a `-wal` sidecar before checkpointing them into the main file, so the base file alone can lag reality by a whole session; its deleted rows are not zeroed but linked onto a freelist and left in place until reused, which is why `.recover` can resurrect them. Whether that recovery works depends on settings you must read rather than assume: `secure_delete=OFF` leaves old bytes in b-tree pages, freeblocks and freelist pages, `FAST` overwrites b-tree pages but leaves freelist pages intact, and `ON` overwrites them. A `VACUUM` rebuilds the file and destroys the remnants outright, and `auto_vacuum=FULL` truncates freelist pages at commit. Postgres writes a write-ahead log you can archive and replay, and MySQL/MariaDB writes redo and binary logs whose `binlog_format` determines whether row changes or statements were recorded — a statement-format binlog proves a statement ran, not which rows it touched. Oracle's redo and undo serve the same roles with different visibility rules. None of these streams record intent or authorship: a row change in a WAL is a row change, an authenticated session in an audit table is a session, and the database cannot tell you which of several clients sharing a credential performed the write. That gap is why the connection-level audit or the application's own log is the corroborating artifact, and why a database examined alone can rarely support an attribution.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the engine is SQLite **THEN** copy the database with every sidecar (`-wal`, `-shm`, `-journal`) keeping base names identical, and open the copy with `immutable=1`; **IF** the engine is a server-class database **THEN** prefer a filesystem snapshot of the data directory plus the archived logs over a live logical dump, because a dump records what a query returned, not what the files held.
2. **IF** the live service is still running **THEN** capture the process list, open connections and the log position before any shutdown; **IF** the service is down **THEN** never start it against the original data directory — startup replay of redo or WAL mutates the evidence.
3. **IF** the question is "what is the current state" **THEN** read the data files; **IF** the question is "what changed and in what order" **THEN** read the transactional stream and normalise its log sequence numbers or LSNs into a single ordering before touching the data.
4. **IF** the question is "was a row deleted" **THEN** branch on engine: SQLite leaves freelist remnants recoverable by `.recover`; Postgres leaves dead tuples until vacuum; MySQL row-format binlogs carry the before-image only if `binlog_row_image` is `FULL`. State which of these applied, because a deleted row that was vacuumed is gone and saying so is the finding.
5. **IF** the timestamp column is nullable, timezone-naive, or written by the application rather than the engine **THEN** treat it as application-supplied data and corroborate against the engine's own log timestamps before placing it on a timeline.
6. **IF** the audit trail is an application table rather than an engine-level audit **THEN** it is writable by the same account that writes the data; a gap in it must be corroborated at the engine or OS level before being called tampering.
7. **IF** telemetry source covering `transaction log` / `deleted rows` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the extraction queries themselves | [`QUERIES.md`](QUERIES.md) | One class per storage class, SQLite through server engines |
| Need flags for read-only open and recovery | [`TOOLS.md`](TOOLS.md) | `sqlite3`, `pg_waldump`, `mysqlbinlog` entry points |
| Database lives in a browser profile | [`browser-and-application-forensics`](../browser-and-application-forensics/SKILL.md) | Epoch and schema ownership sit there |
| Need to place row changes on a host timeline | [`log-and-timeline-analysis`](../log-and-timeline-analysis/SKILL.md) | Cross-source normalisation |
| Need the file's own filesystem history | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | MFT/USN evidence around the data directory |
| Need a scripted recovery pipeline | [`sqlite-wal-and-browser-artifact-scripting`](../../security-automation-and-tool-development/sqlite-wal-and-browser-artifact-scripting/SKILL.md) | Automation ownership |
| Need the OS account that wrote the files | [`linux-forensics`](../linux-forensics/SKILL.md) or [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | Host-level attribution |
| Need known shapes of data-theft and wipe cases | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the SHA-256 of every data file, sidecar and archived log, and record whether the capture was a filesystem snapshot, a service-aware backup, or a live copy. Open SQLite copies with `immutable=1`; open server databases only on a restored copy with the service stopped, because starting the engine replays logs and rewrites the very files under examination.
2. **Choose the branch from the engine and the question.** Current-state questions read the data files; ordering questions read the transactional stream; deleted-data questions read the remnants appropriate to that engine. Write the engine version and its `secure_delete` and `auto_vacuum` settings into the output, because both determine whether deleted content survived and whether free pages were returned to the filesystem.
3. **Establish a baseline-versus-probe differential.** Baseline is the table's own historical distribution of change rate, the engine's normal checkpoint cadence, or a peer instance of the same schema. Probe is the incident window. The finding is a delta — a table that stops receiving writes while its neighbours continue, a checkpoint interval that changes, a sequence of `DELETE`s without matching application traffic.
4. **Name the stop condition.** Declare `Inconclusive` when a `VACUUM` or `auto_vacuum=FULL` has removed the remnants, when the WAL was checkpointed and deleted on clean shutdown, when binlogs were purged by retention, when the log position was reset by a restart you cannot bound, or when only application-written audit rows survive with no engine-level corroboration.
5. **State what counts as proof.** Proof is two independent records agreeing inside a stated tolerance: a binlog or WAL entry for the write plus the engine's own transaction timestamp, or a recovered row plus a filesystem record of the write at that time. A recovered fragment without rowid or table attribution is content, not an event, and must be labelled as such.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `visits`/`downloads`-style rows present in `-wal` frames but absent from the base SQLite file | SQLite WAL sidecar | Activity committed after the last checkpoint; the newest state on any SQLite evidence |
| Rows recovered from freelist pages with intact cell structure | SQLite freelist and unallocated page space | A row of that shape existed and was deleted while `secure_delete` was off; rowid may survive, attribution may not |
| `DELETE`/`INSERT` pairs for one table inside a single transaction in a row-format binlog | MySQL binary log (`binlog_format=ROW`) | Exactly which rows changed and their before-images when `binlog_row_image=FULL`; statement-format logs prove only that a statement ran |
| WAL records for a table with a commit timestamp outside application traffic windows | Postgres WAL (via `pg_waldump`) | A transaction committed at that time on that database; the session identity is not in the WAL |
| Dead tuples still visible through an old snapshot | Postgres MVCC dead-tuple chain | A row version existed and was superseded without vacuum yet reclaiming it |
| Audit or `general_log` entry naming a client host and user for the same window | Engine audit log or connection log | Which credentialed client issued the statement; the credential may be shared, so this identifies a session, not a person |
| Data file whose `change counter` or header sequence moves between two of your own copies | SQLite file header (offset 24) | The file was written between the two acquisitions; a header that never moves while you know writes occurred means you are reading a stale copy |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Reads the live database, trusts an application audit table, and counts rows.
sqlite3 /var/app/app.db "select count(*) from audit_log where action='DELETE';"
# No sidecar handling, so the WAL is not read; no epoch or timezone check on the
# audit rows; and the audit table is writable by the same account as the data,
# so an empty result proves only that the table is empty now.
```

**High-Signal Grounded Artifact:**

```sqlite
-- Work on a copy that includes -wal and -shm, opened immutable.
ATTACH DATABASE 'file:/cases/07/app.db?immutable=1' AS a;
PRAGMA a.journal_mode;            -- expect wal on a modern app database
PRAGMA a.integrity_check;         -- refuse to interpret a failing database
SELECT name FROM a.sqlite_schema WHERE type='table';

-- Live view: what the engine considers current, with the file's own counter.
PRAGMA a.data_version;
SELECT COUNT(*) AS rows_now FROM a.audit_log;

-- Then recover beyond the live view, and compare the two results.
-- sqlite3 'file:/cases/07/app.db?immutable=1' ".recover" > recovered.sql
```

**Why this matters:** the strong form refuses to read a database it has not health-checked, states the journal mode so the reader knows whether a WAL existed, records the header counter so a stale copy is detectable, and pairs the live count with a recovery pass instead of trusting a single writable table.

## When It Is NOT This Issue

- **Routine maintenance rewriting files:** `VACUUM`, `OPTIMIZE TABLE`, index rebuilds and `pg_repack` all rewrite data files and change file timestamps and internal counters. A file that changed without matching application writes is maintenance until proven otherwise.
- **Timezone and type confusion:** a `DATETIME` column stored naive in local time, an epoch stored in seconds in one table and milliseconds in another, and `TIMESTAMP` columns converted by the driver all produce plausible-looking timelines that are systematically wrong. Check the column type and the driver's timezone setting.
- **Replication and failover:** a replica promoted during the window writes its own logs with a new timeline and sequence numbering, so a log position that resets is a topology event, not tampering. Read the server's own log for `promote` or `failover` records.
- **Retention and purge jobs:** binlog purge, WAL recycling and audit-log rotation remove history on a schedule. A short stream is the configured retention until you can show the configuration changed.
- **Shared application credentials:** many applications connect with one database user, so every row in the engine's audit names the same principal. Absence of a distinguishable user is a design property, not evidence of a cover-up.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `transaction log` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** every data file, sidecar and archived log used carries a recorded SHA-256, and the acquisition method is stated.
- [ ] **Engine and branch stated:** engine, version, journal or binlog mode, and recovery-relevant settings (`secure_delete`, `binlog_row_image`, archive mode) are recorded.
- [ ] **Differential defined:** a historical or peer baseline was compared against the incident window, and the finding is the delta in change rate or ordering.
- [ ] **Stop condition cleared or declared:** vacuum, checkpoint, purge, failover and unwritable-audit limits were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: database-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `database-forensics` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — never start a database service against original evidence, and never run `VACUUM`, `OPTIMIZE` or a repair utility on a file you have not copied.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (3), CYBER_CPT/nuclei_templates (3), CYBER_CPT/hacktricks (2), ctf-solver-dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
