# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-methodology-collection-and-logging`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** SQLite with WAL, canonical JSON (`sort_keys=True`) for hashing, append-only insert path.
- **Validation Gate:** a completeness query returning zero rows with a null provenance field.
- Never UPDATE a logged row; corrections are new rows that cite the superseded id.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 osint.db ".schema log"` | Confirm the log schema before collection | Cross-platform |
| `jq` | `jq -S -c . raw.json > canonical.json` | Write the canonical JSON, then hash canonical.json with sha256sum outside the collector | Linux, macOS |
| `date` | `date -u +%Y-%m-%dT%H:%M:%SZ` | Record timestamps in UTC so records from different analysts sort | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib, json, sqlite3, time

con = sqlite3.connect("osint.db", isolation_level=None)
con.execute("PRAGMA journal_mode=WAL")
con.execute("CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY, analyst TEXT, source TEXT, query TEXT, fetched_at TEXT, raw_sha256 TEXT, raw TEXT)")

def log(analyst, source, query, payload):
    raw = json.dumps(payload, sort_keys=True)
    con.execute("INSERT INTO log (analyst, source, query, fetched_at, raw_sha256, raw) VALUES (?,?,?,?,?,?)",
                (analyst, source, query, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 hashlib.sha256(raw.encode()).hexdigest(), raw))
```
