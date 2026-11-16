# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`physical-and-facility-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** address-keyed registry search, planning portal queries, and imagery with capture dates.
- **Validation Gate:** one address resolved to a coordinate and one occupant list retrieved before any site description.
- Imagery providers differ in capture cadence and licensing; record provider and date, and respect the licence for any reproduced image.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://registry.example/search?address=AB1%202CD'` | Entities registered at an address | Cross-platform |
| `jq` | `jq ".results[].status" out.json` | Read entity status from a registry response | Linux, macOS |
| `exiftool` | `exiftool -a -G1 -s site.jpg` | Metadata on any locally held site image | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("osint.db")
con.execute("CREATE TABLE IF NOT EXISTS site (id INTEGER PRIMARY KEY, address TEXT, entity TEXT, source TEXT, retrieved_at TEXT)")
for addr, ent, src, at in con.execute("SELECT address, entity, source, retrieved_at FROM site"):
    print(json.dumps({"address": addr, "entity": ent, "source": src, "retrieved_at": at}))
```
