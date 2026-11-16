# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`geolocation-and-imagery-verification-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** EXIF reading with `exiftool`, sun-position computation for the stated date and time, and OpenStreetMap feature queries via Overpass.
- **Validation Gate:** one shadow measurement compared with a computed sun position, and one feature confirmed on map data.
- Most social platforms strip EXIF; a surviving timestamp usually comes from the API, not the file, so record which one you have.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `exiftool` | `exiftool -a -G1 -s image.jpg` | All metadata groups including GPS and timestamps | Cross-platform |
| `overpass` | `curl -sS -G 'https://overpass-api.de/api/interpreter' --data-urlencode 'data=...'` | Query map features near a candidate coordinate | Cross-platform |
| `astral` | `python -c "from astral.sun import elevation; print('ok')"` | Compute sun elevation and azimuth for a candidate time and place | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("osint.db")
con.execute("CREATE TABLE IF NOT EXISTS geo (id INTEGER PRIMARY KEY, artefact TEXT, technique TEXT, value TEXT, tolerance TEXT, observed_at TEXT)")
for row in con.execute("SELECT artefact, technique, value, tolerance FROM geo"):
    print(json.dumps({"artefact": row[0], "technique": row[1], "value": row[2], "tolerance": row[3]}))
```
