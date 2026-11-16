# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`mobile-device-forensics`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for mobile acquisition and parsing. Commercial extraction suites are covered at the capability level rather than with invented flags — always take the exact command from the tool's own `--help` or release notes for your build, since coverage lists change with every release.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Cellebrite UFED / Inspector | GUI acquisition and parsing; check the release notes for the model and OS coverage matrix | AFU/BFU access and full file system extraction on supported builds | Windows |
| MSAB XRY | GUI acquisition; release notes list per-model extraction depth | Logical and full file system extraction, iOS backup decoding | Windows |
| Belkasoft X | GUI acquisition; checkm8 (A7–A11) and agent-based methods documented separately | Full file system plus keychain where the method supports it | Windows |
| `libimobiledevice` (`idevicebackup2`) | `idevicebackup2 backup --full ./backup` | Logical iOS backup, unencrypted unless the device password is supplied | Cross-platform |
| `adb` | `adb backup -apk -shared -all -system` (only where the build still supports it) | Android logical backup on permissive builds | Cross-platform |
| `aleapp` / `iLEAPP` | `python aleapp.py -t tar -i ./extraction.tar -o ./out` | Open-source parsers for Android and iOS artefact sets, preserving media capture times | Cross-platform |

## Minimal Script Shape

The shape below records scope before content, opens every database read-only against mutation, and refuses to describe an unreadable database as an empty one.

```python
#!/usr/bin/env python3
"""mobile-triage.py — scope record, read-only database inventory, recency bounds."""
import hashlib, os, sqlite3, sys

EXTRACT = sys.argv[1] if len(sys.argv) > 1 else "./extraction"
SCOPE_FIELDS = ("model", "os_build", "lock_state", "extraction_class", "tool_version")

def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()

# 1. Scope first: these five values bound every claim that follows.
print("== acquisition scope (fill from the acquisition record) ==")
for field in SCOPE_FIELDS:
    print(f"  {field:18}= ")

# 2. Container hashes for the evidence register.
for root, _, files in os.walk(EXTRACT):
    for name in files:
        if name.endswith((".tar", ".zip", ".dd", ".img", ".ab")):
            path = os.path.join(root, name)
            print(f"  evidence {sha256(path)[:16]}  {os.path.getsize(path):>12}  {path}")

# 3. Database inventory: immutable read, explicit unreadable handling.
print("== databases ==")
for root, _, files in os.walk(EXTRACT):
    for name in sorted(files):
        if not name.endswith((".db", ".sqlite", ".sqlite3")):
            continue
        path = os.path.join(root, name)
        uri = f"file:{path}?mode=ro&immutable=1"
        try:
            con = sqlite3.connect(uri, uri=True)
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            total = 0
            for t in tables:
                total += con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            print(f"  OK  tables={len(tables):3d} rows={total:8d}  {path}")
            con.close()
        except sqlite3.DatabaseError as exc:
            print(f"  UNREADABLE (expect WAL or encryption): {path} :: {exc}")
```

## Notes That Prevent Wrong Runs

- Open databases with `mode=ro&immutable=1`. Any other mode lets SQLite checkpoint the WAL and modify the evidence tree.
- Copy `-wal` and `-shm` files with their database. A database copied alone can present a state days older than the device.
- checkm8-class extraction applies to A7 through A11 hardware only; agent-based methods cover different and broader model ranges. Confirm against the release notes for your exact tool build rather than assuming parity.
- `adb backup` is unavailable or restricted on many current Android builds. Treat a failure as a coverage limitation and record it, rather than falling back silently to manual review and describing the result as complete.
