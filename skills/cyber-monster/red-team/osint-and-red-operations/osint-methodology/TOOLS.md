# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-methodology`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a plan document plus SQLite for observations; every row carries `source`, `fetched_at`, `raw_sha256`.
- **Validation Gate:** a coverage query showing zero observations with missing provenance before any report is drafted.
- Record the retrieval tool and its version too: a registry API answer is only reproducible with the same client semantics.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 osint.db ".schema obs"` | Confirm the provenance schema before collecting | Cross-platform |
| `jq` | `jq -S . raw.json > canonical.json` | Write the canonical JSON, then hash canonical.json with sha256sum | Linux, macOS |
| `curl` | `curl -sS -D- -o raw.json https://rdap.example/domain/target.example` | Retrieve a record with its response headers for the timestamp record | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib, json, sqlite3, time

con = sqlite3.connect("osint.db", isolation_level=None)
con.execute("PRAGMA journal_mode=WAL")
con.execute("CREATE TABLE IF NOT EXISTS obs (id INTEGER PRIMARY KEY, source TEXT, query TEXT, fetched_at TEXT, raw_sha256 TEXT, payload TEXT)")

def store(source, query, payload):
    blob = json.dumps(payload, sort_keys=True).encode()
    con.execute("INSERT INTO obs (source, query, fetched_at, raw_sha256, payload) VALUES (?,?,?,?,?)",
                (source, query, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 hashlib.sha256(blob).hexdigest(), blob.decode()))
```
