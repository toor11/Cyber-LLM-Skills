# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sqlite-wal-and-browser-artifact-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — check the installed SQLite/Python versions if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11+ `sqlite3` with URI filenames (`?mode=ro`, `?mode=rw`), `contextlib.closing` for deterministic handle release, `hashlib.sha256` streamed in 1 MB chunks
- **Schema:** Chromium/Edge `urls` + `visits` (WebKit microseconds since 1601-01-01 UTC); Firefox `moz_places` + `moz_historyvisits`
- **Validation Gate:** `python -m py_compile parse_browser_db.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Python `sqlite3` | `sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)` | Open the snapshot read-only through a URI filename | Python 3.11+ |
| Python `sqlite3` | `sqlite3.connect(f"{path.as_uri()}?mode=rw", uri=True)` | Open read-write on the copy so a rollback journal can be applied | Python 3.11+ |
| Python `contextlib` | `contextlib.closing(conn)` | Close the handle deterministically; the `sqlite3` context manager only commits/rolls back | Python 3.11+ |
| Python `hashlib` | `hashlib.sha256()` over `iter(lambda: fh.read(1 << 20), b"")` | Stream a large evidence file without loading it | Python 3.11+ |
| Python `pathlib` | `pathlib.Path.as_uri()` | Produce a correct `file:///` URI for Windows paths | Python 3.11+ |
| Python `tempfile` | `tempfile.mkdtemp(prefix="forensic_sqlite_")` | Isolated working directory for the copy | Python 3.11+ |
| PowerShell | `Get-FileHash <path> -Algorithm SHA256` | Independent hash computation for the manifest | Windows PowerShell 5.1 |
| SQLite CLI | `sqlite3 -readonly snapshot.db ".tables"` | Enumerate tables on the copy when scripting is unnecessary | Cross-platform |

## Minimal Script

```powershell
$src  = "C:\evidence\History"
$work = "C:\work\sqlite-snapshot"
New-Item -ItemType Directory -Force -Path $work | Out-Null

$before = Get-FileHash $src -Algorithm SHA256
Copy-Item $src "$work\History" -Force
if (Test-Path "$src-wal")     { Copy-Item "$src-wal" "$work\History-wal" -Force }
if (Test-Path "$src-journal") { Copy-Item "$src-journal" "$work\History-journal" -Force }

python .\parse_browser_db.py "$work\History" | Set-Content "$work\recent-urls.json"
$parse = $LASTEXITCODE

$after = Get-FileHash $src -Algorithm SHA256
if ($before.Hash -ne $after.Hash) { Write-Output "evidence hash drift"; exit 1 }
if ($parse -ne 0) { Write-Output "extraction failed: $parse"; exit 2 }
```

Exit-code contract: `0` manifests match and rows were extracted, `1` hash drift or implausible timestamp, `2` missing database, unreadable snapshot, or unclosed handle.
