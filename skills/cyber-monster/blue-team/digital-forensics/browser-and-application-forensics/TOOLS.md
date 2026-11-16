# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`browser-and-application-forensics`](SKILL.md) | Family: **Digital Forensics**

Entry points for reading browser and application state out of an acquired profile. Never invent undocumented flags — confirm with `--help` on the installed build, because Hindsight's option surface and Chromium's schema both move between releases. Every invocation here is read-only against a copy.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Hindsight` | `hindsight.py -i "<profile dir>" -o <out> -f xlsx` | One-pass extraction of Chromium, Firefox and Safari history, downloads, cookies and logins | Windows, macOS, Linux |
| `sqlite3` (CLI) | `sqlite3 'file:<db>?immutable=1' "PRAGMA integrity_check;"` | Read-only open plus health check before any query | Cross-platform |
| `sqlite3 .recover` | `sqlite3 'file:<db>?immutable=1' ".recover"` | Carve deleted rows from freelist and unallocated page space | Cross-platform |
| `BrowsingHistoryView` | `BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 1 /scomma out.csv` | Read every installed browser's history from an offline profile tree | Windows |
| `Plaso` | `log2timeline.py --storage-file profile.plaso <mount>` | Fold browser artifacts into a super timeline with OS artifacts | Cross-platform |
| `The Sleuth Kit` | `fls -r -p -o <sector> <image>` then filter the listing for profile database names | Locate profile databases inside a disk image without mounting | Cross-platform |

## Minimal Script Shape

The shape below inventories the profiles it finds, hashes each database with its sidecars, and refuses to report activity from a database that fails an integrity check.

```python
#!/usr/bin/env python3
"""profile-inventory.py — read-only inventory of an offline browser profile tree."""
import hashlib
import pathlib
import sqlite3
import sys

SIDECARS = ("-wal", "-shm", "-journal")

def digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def integrity(db: pathlib.Path) -> str:
    try:
        con = sqlite3.connect(f"file:{db}?immutable=1", uri=True)
        return con.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.Error as exc:
        return f"ERROR: {exc}"

root = pathlib.Path(sys.argv[1])
names = ("History", "places.sqlite", "History.db", "Cookies", "Login Data", "Web Data")
for db in sorted(p for p in root.rglob("*") if p.name in names):
    side = [s for s in SIDECARS if (db.parent / (db.name + s)).exists()]
    print(f"{db}\tsha256={digest(db)}\tsidecars={side or 'none'}\tintegrity={integrity(db)}")
```

## Notes That Prevent Wrong Runs

- `immutable=1` is not a nicety. Without it SQLite may create a rollback journal beside the copy and checkpoint the WAL into the base file, deleting the newest visits and changing your evidence in one step.
- Copy `History`, `History-wal` and `History-shm` together and keep the base names identical; SQLite binds a WAL to its database by filename and a renamed WAL is silently ignored.
- `Hindsight` normalises epochs for you. If you also run raw SQL, verify one timestamp from the Hindsight output against your own conversion before publishing a timeline built from both.
- Profile directories can be nested (`Default`, `Profile 1`, `Guest Profile`, and per-account `Profile 2` for managed accounts). Enumerate them all; analysing only `Default` is a common, silent scope error.
- On a live system the browser holds the database open. Copying an open SQLite file with a plain file copy can capture a torn write; prefer a VSS snapshot or stop the browser only after memory has been captured.
