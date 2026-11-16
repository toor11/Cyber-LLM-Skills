# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`corporate-and-person-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** RDAP or registry JSON for the organisation anchor, page captures for people sources, a provenance store with `verified` flags.
- **Validation Gate:** a query showing at least two verified addresses before any convention is applied.
- Respect each platform's terms and rate limits; a directory scrape that violates them invalidates the collection.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS https://rdap.example/domain/target.example` | Registry record for the organisation anchor | Cross-platform |
| `jq` | `jq ".entities[].handle" rdap.json` | Extract entity handles from a registry response; roles sit on the same objects | Linux, macOS |
| `dig` | `dig +short MX target.example` | Confirm the mail provider, which constrains address conventions | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("osint.db")
rows = con.execute("SELECT address, source, published_at FROM addresses WHERE verified = 1").fetchall()
formats = {}
for address, source, published_at in rows:
    local, _, domain = address.partition("@")
    shape = "f.last" if "." in local else "unknown"
    formats.setdefault(shape, []).append((address, source))
print(json.dumps({k: len(v) for k, v in formats.items()}))
```
