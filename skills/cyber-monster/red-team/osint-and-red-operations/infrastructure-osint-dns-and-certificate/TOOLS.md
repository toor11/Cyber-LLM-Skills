# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`infrastructure-osint-dns-and-certificate`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** authoritative DNS via `dig`, passive DNS and CT as historical sources, with the interface and date recorded per observation.
- **Validation Gate:** an `NXDOMAIN` or current-address answer from the authoritative server before any name is called an asset.
- Certificate transparency log interfaces changed materially in 2025-2026: logs moved to a static API and some legacy endpoints were withdrawn, so record which interface returned a record.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +trace target.example` | Delegation path and authoritative answer | Cross-platform |
| `dig` | `dig +short NS target.example` | Nameserver pair for association signals | Cross-platform |
| `curl` | `curl -sS 'https://crt.sh/?q=%25.target.example&output=json'` | Certificate transparency names with issuance dates | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json, sqlite3

con = sqlite3.connect("osint.db")
con.execute("CREATE TABLE IF NOT EXISTS dns_obs (id INTEGER PRIMARY KEY, name TEXT, kind TEXT, value TEXT, seen_at TEXT)")
for name, kind, value, seen in con.execute("SELECT name, kind, value, seen_at FROM dns_obs ORDER BY id DESC LIMIT 10"):
    print(json.dumps({"name": name, "kind": kind, "value": value, "seen_at": seen}))
```
