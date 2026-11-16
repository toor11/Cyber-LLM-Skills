# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`database-forensics`](SKILL.md) | Family: **Digital Forensics**

Read-only entry points for examining database evidence. Never invent undocumented flags — confirm with `<tool> --help` on the installed version, because `mysqlbinlog`'s decode options and `pg_waldump`'s range syntax differ across major releases. Nothing here starts a service against original evidence or runs maintenance on a file you have not copied.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` (CLI) | `sqlite3 'file:<db>?immutable=1' "PRAGMA integrity_check;"` | Read-only open, health and settings inspection | Cross-platform |
| `sqlite3 .recover` | `sqlite3 'file:<db>?immutable=1' ".recover" > out.sql` | Carve rows from freelist and unallocated page space | Cross-platform |
| `mysqlbinlog` | `mysqlbinlog --base64-output=DECODE-ROWS -v <binlog>` | Decode row events with before-images into readable form | Cross-platform |
| `pg_waldump` | `pg_waldump -p <pg_wal dir> -s <lsn> -e <lsn>` | Read the Postgres WAL from a copied archive | Cross-platform |
| `pg_checksums` | `pg_checksums --check --pgdata <copy>` | Verify page checksums on a stopped copy | Cross-platform |
| `ausearch` | `ausearch -if <audit.log> -k <key> -i` | Corroborate file writes to the data directory from the OS | Linux |

## Minimal Script Shape

The shape below opens a SQLite copy safely, records the settings that determine whether deleted rows are recoverable, and refuses to report recovery numbers without stating which mode produced them.

```python
#!/usr/bin/env python3
"""sqlite-evidence-gate.py — read-only settings and recovery gate for a SQLite copy."""
import pathlib
import sqlite3
import sys

db = pathlib.Path(sys.argv[1])
sidecars = [s for s in ("-wal", "-shm", "-journal") if (db.parent / (db.name + s)).exists()]

con = sqlite3.connect(f"file:{db}?immutable=1", uri=True)
read = lambda q: con.execute(q).fetchall()

print("sidecars:", sidecars or "none (clean shutdown or sidecars not copied)")
print("journal_mode:", read("PRAGMA journal_mode")[0][0])
print("page_size:", read("PRAGMA page_size")[0][0],
      "page_count:", read("PRAGMA page_count")[0][0],
      "freelist:", read("PRAGMA freelist_count")[0][0])
print("secure_delete:", read("PRAGMA secure_delete")[0][0])
print("auto_vacuum:", read("PRAGMA auto_vacuum")[0][0])
print("integrity_check:", read("PRAGMA integrity_check")[0][0])

if "".join(read("PRAGMA journal_mode")[0]) == "wal" and "-wal" not in sidecars:
    print("GAP: WAL mode but no -wal present -> newest state may be missing")
if read("PRAGMA integrity_check")[0][0] != "ok":
    print("STOP: integrity check failed -> report fragments only, no live queries")
con.close()
```

## Notes That Prevent Wrong Runs

- `immutable=1` prevents SQLite from creating a rollback journal or checkpointing the WAL into the copy. Without it, opening the database changes the evidence you are about to describe.
- `PRAGMA secure_delete` reports the setting in force for the connection, which for a copied file may not be the setting the application used at deletion time. Treat it as a hint and corroborate with what the recovery actually yields.
- `mysqlbinlog --read-from-remote-server` reads from the server; `--raw` copies the file. Copy first, decode second, so the decode runs against a fixed artifact you can hash.
- `pg_waldump` needs a WAL segment directory, not a running cluster. On a stopped copy, check that `pg_controldata` agrees with the segment names before trusting the LSN range.
- A logical dump (`pg_dump`, `mysqldump`) is not a forensic acquisition: it records query output and drops free space, page layout and most remnants. Use it only for schema reference.
