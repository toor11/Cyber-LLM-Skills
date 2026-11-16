# Artifacts and Queries

> Sub-skill: [`database-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction queries owned by `database-forensics`, grouped by storage class. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Every statement is read-only and runs against a copy; none performs maintenance, repair or schema change. Confirm column and view names against the actual schema — they differ by engine version and by application.

## Class 1 — Integrity and read-only gate

Expected hit: a copy that passes an integrity check, with every sidecar present and a recorded digest. A database that fails here cannot be queried for anything but fragments.

```bash
ls -la /cases/07/app.db*                       # base plus -wal / -shm / -journal
sha256sum /cases/07/app.db* | tee manifest.txt
sqlite3 'file:/cases/07/app.db?immutable=1' \
  "PRAGMA journal_mode; PRAGMA page_count; PRAGMA freelist_count; PRAGMA integrity_check;"
```

```sql
-- Postgres: on a restored copy, never the original cluster.
SELECT pg_is_in_recovery(), current_setting('archive_mode'), current_setting('wal_level');
SELECT pg_current_wal_lsn();
```

False-positive note: `page_count` and `freelist_count` describe the file, not the logical database, and both change after a checkpoint. Take them twice before using either as evidence of a write.

## Class 2 — SQLite live state versus recovered state

Expected hit: a live count and a recovered count that differ, with the difference explainable. Rows present only in the recovery output are deletions; rows present only in the live view prove the recovery output is incomplete or the wrong file.

```sqlite
ATTACH DATABASE 'file:/cases/07/app.db?immutable=1' AS a;
SELECT name, type FROM a.sqlite_schema ORDER BY type, name;
PRAGMA a.data_version;
SELECT COUNT(*) FROM a.audit_log;
SELECT * FROM a.audit_log ORDER BY rowid DESC LIMIT 20;
```

```bash
# Recovery outside the live view; freelist included and excluded, then compared.
sqlite3 'file:/cases/07/app.db?immutable=1' ".recover"                > rec-free.sql
sqlite3 'file:/cases/07/app.db?immutable=1' ".recover --ignore-freelist" > rec-strict.sql
grep -c '^INSERT INTO' rec-free.sql rec-strict.sql
```

False-positive note: `.recover` reintroduces content that a legitimate `VACUUM` or schema migration removed, and it may reassign rows to a `lost_and_found` table. Without a rowid a recovered row cannot be placed in time, and reporting it as an event is a misstatement.

## Class 3 — Server-engine change streams

Expected hit: transaction entries for the window, with row before-images where the configuration supports them, converted to UTC and ordered by log position.

```bash
# MySQL/MariaDB: read the binlog rather than the live server.
mysqlbinlog --read-from-remote-server --host=db01 --user=ro --raw \
  --result-file=/cases/07/binlog- --stop-datetime="$END" mysql-bin.000017
mysqlbinlog --base64-output=DECODE-ROWS -v /cases/07/binlog-mysql-bin.000017 \
  | grep -E '^### (DELETE|INSERT|UPDATE)' | head -40
```

```bash
# Postgres: decode the WAL from a copy of the archive.
pg_waldump -p /cases/07/pg_wal -s "$START_LSN" -e "$END_LSN" 2>/dev/null \
  | grep -E 'rmgr: (Heap|Btree|Transaction)' | head -40
```

False-positive note: a statement-format binlog records SQL text, not rows, so it cannot show which rows changed; and `binlog_row_image=MINIMAL` omits before-images entirely. Check both settings before claiming to know what a `DELETE` removed.

## Class 4 — Deleted or superseded row remnants

Expected hit: evidence that a row version existed, with an explicit statement of where the remnant lived and what attribution it lost.

```sql
-- Postgres: dead tuples visible through an old snapshot, if not yet vacuumed.
SELECT relname, n_dead_tup, n_live_tup, last_vacuum, last_autovacuum
FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 20;
```

```bash
# SQLite: which page held the remnant and whether freelist or unallocated space.
sqlite3 'file:/cases/07/app.db?immutable=1' \
  "SELECT name FROM sqlite_schema WHERE rootpage > 0 ORDER BY rootpage;" > rootpages.txt
grep -n 'INSERT INTO' rec-free.sql | head -5   # compare against rootpages.txt by table name
```

False-positive note: `n_dead_tup` counts rows awaiting vacuum, which includes ordinary `UPDATE` churn — a busy table always has dead tuples. Only a dead tuple matching a specific value is evidence about that row.

## Class 5 — Connection, statement and audit records

Expected hit: a session record naming client host, user and time, matching the change stream's window. A change with no matching session means the audit was off or the session record was removed.

```sql
-- Postgres: engine-level statement logging, if configured.
SELECT to_char(log_time,'YYYY-MM-DD HH24:MI:SS'), user_name, database_name,
       client_addr, command_tag, message
FROM postgres_log
WHERE log_time BETWEEN :start AND :end AND command_tag IN ('DELETE','TRUNCATE','UPDATE')
ORDER BY log_time LIMIT 200;
```

```bash
# MySQL/MariaDB: general or audit log, if enabled at the time.
grep -E 'Query.*(DELETE|DROP|TRUNCATE)' /cases/07/mysql-general.log | head -40
```

False-positive note: these tables and files exist only if logging was enabled when the event happened; enabling them afterwards and querying for the past returns nothing and proves nothing. Record the setting's history before interpreting an empty result.

## Class 6 — File-level write corroboration

Expected hit: filesystem records of the data directory being written at the times the engine claims, from an independent source (USN journal, ext4 journal, auditd watch).

```bash
# Linux: auditd watch records for the data directory, if a watch existed.
ausearch -if /cases/07/audit.log -k dbdir -i --start "$START_DATE" --end "$END_DATE" | head -60
```

```powershell
# Windows: USN records for the database path, from a copied $J.
MFTECmd.exe -f "D:\evidence\DB01\$J" -m "D:\evidence\DB01\$MFT" --csv D:\out --csvf usn-db.csv
Import-Csv D:\out\usn-db.csv | Where-Object { $_.Name -match '\.(mdf|ldf|ibd|db|sqlite)$' } |
  Sort-Object UpdateTimestamp | Select-Object UpdateTimestamp, Name, UpdateReasons -First 40
```

False-positive note: a database's files are written by checkpointing and background flushing, so filesystem writes do not map one-to-one onto transactions. Use them to prove the engine was active, not to date a specific row change.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, beside every database finding, the engine version, the journal or binlog mode, and whether audit logging was enabled during the window; without those three the finding cannot be reviewed.
