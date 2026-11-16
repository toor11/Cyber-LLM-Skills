# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-collector-and-entity-graph-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python `sqlite3` with WAL journaling, `httpx` for retrieval, SHA-256 over a canonical JSON encoding for the payload hash.
- **Validation Gate:** one collection run followed by a `SELECT` that shows `source`, `fetched_at`, and `raw_sha256` populated for every row.
- Canonicalise JSON (`sort_keys=True`) before hashing, otherwise a key-order change looks like a source change.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 osint.db ".schema obs"` | Confirm the provenance columns exist before collecting | Cross-platform |
| `httpx` | `python -c "import httpx; print(httpx.__version__)"` | Pin the client version whose redirect behaviour you rely on | Cross-platform |
| `jq` | `jq -S . raw.json > canonical.json` | Write the canonical JSON, then hash canonical.json outside the collector | Linux, macOS |

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

store("certificate-transparency", "target.example", {"cn": "target.example"})
print(con.execute("SELECT COUNT(*) FROM obs").fetchone()[0])
```
