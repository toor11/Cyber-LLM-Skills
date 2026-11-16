# Artifacts and Queries

> Sub-skill: [`browser-and-application-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction queries and artifact-location checks owned by `browser-and-application-forensics`. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Every block reads a copy; none writes to the profile. Confirm the epoch and column names against the profile's own schema before trusting output, because Chromium's schema changes between major versions.

## Class 1 — Profile inventory and read-only gate

Expected hit: one row per profile with a database size and a sidecar inventory. A profile with `History` but no `-wal` was almost certainly shut down cleanly before acquisition, which changes how much recent activity you can recover.

```bash
# Copy the profile first, then inventory. Never point the parser at the live profile.
PROFILE="/evidence/HOST01/Users/bob/AppData/Local/Google/Chrome/User Data/Default"
ls -la "$PROFILE"/{History,History-wal,History-shm,Cookies,Login\ Data,Web\ Data,Preferences} 2>/dev/null
sha256sum "$PROFILE"/History* 2>/dev/null
```

```powershell
# Windows equivalent: inventory every profile under the User Data root.
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Directory |
  Where-Object { Test-Path (Join-Path $_.FullName 'History') } |
  ForEach-Object {
    Get-ChildItem $_.FullName -Filter 'History*' |
      Select-Object @{n='Profile';e={$_.Directory.Name}}, Name, Length, LastWriteTimeUtc
  }
```

False-positive note: `LastWriteTimeUtc` on `History` reflects the last SQLite write, not the last visit; a profile opened and closed with no navigation still updates it. Use the row timestamps for activity, not the file time.

## Class 2 — Chromium visit timeline (epoch-correct)

Expected hit: visit rows converted to UTC inside a stated window, joined to their URLs, with `transition` preserved. An empty result inside a window where the profile clearly existed is a stop condition, not a clean result.

```sqlite
-- Copy History, History-wal and History-shm to one directory first.
-- immutable=1 prevents SQLite from checkpointing and rewriting the copy.
ATTACH DATABASE 'file:/cases/01/History?immutable=1' AS h;
SELECT datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS visited_utc,
       u.url, u.title, v.transition, v.visit_duration, u.typed_count, v.from_visit
FROM h.visits v
JOIN h.urls u ON u.id = v.url
WHERE u.url NOT LIKE 'chrome://%'
ORDER BY v.visit_time DESC
LIMIT 500 OFFSET 0;
```

False-positive note: `visit_duration` of `0` means "not recorded" and does not mean the page was closed instantly; older builds never populated it. `typed_count` counts lifetime deliberate entries, not the entry you are looking at, so it must never be read as "the user typed this URL at this time".

## Class 3 — Downloads, including cancelled and dangerous

Expected hit: `state` and `danger_type` per row with a converted `start_time`, plus the `target_path`. A `state=2` row is a cancelled attempt and must not be reported as a fetched file.

```sqlite
SELECT datetime(d.start_time/1000000 - 11644473600, 'unixepoch') AS started_utc,
       datetime(d.end_time/1000000   - 11644473600, 'unixepoch') AS ended_utc,
       d.state, d.danger_type, d.interrupt_reason, d.total_bytes, d.received_bytes,
       d.target_path, d.tab_url, d.referrer, d.by_ext_name, d.mime_type
FROM downloads d
ORDER BY d.start_time DESC;
```

False-positive note: Chrome reuses `target_path` and marks the earlier row `interrupted` when a download is resumed or renamed, so several rows can describe one file. De-duplicate on `guid` before counting downloads, and check `by_ext_name` before attributing a download to the user's click.

## Class 4 — Recovery from WAL, freelist and carved pages

Expected hit: rows that exist in the WAL but not in the base file (recent activity), and old rows recovered from freelist pages (cleared activity). Presence in WAL is exact; presence in freelist is partial and loses rowid attribution.

```bash
# WAL frame history without letting SQLite merge and checkpoint it.
sqlite3 'file:/cases/01/History?immutable=1' "PRAGMA journal_mode; PRAGMA integrity_check;"
sqlite3 'file:/cases/01/History?immutable=1' ".recover --ignore-freelist" > history-strict.sql
sqlite3 'file:/cases/01/History?immutable=1' ".recover" > history-with-free.sql
wc -l history-strict.sql history-with-free.sql
```

False-positive note: `.recover` resurrects rows the browser deleted, which is the point, but it also reintroduces content that a `VACUUM` legitimately removed during a schema migration. Without a rowid you cannot place a recovered visit on a timeline — report it as content, not as an event.

## Class 5 — Firefox and Safari equivalents

Expected hit: Firefox visits with Unix-microsecond timestamps and Safari visits with Mac absolute time, both converted before comparison. A ported query that leaves the epoch unchanged will show dates centuries away from the corroborating evidence.

```sqlite
-- Firefox: places.sqlite, Unix microseconds.
SELECT datetime(h.visit_date/1000000, 'unixepoch') AS visited_utc,
       p.url, p.title, h.visit_type
FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id
ORDER BY h.visit_date DESC LIMIT 100;

-- Safari: History.db, Mac absolute time (seconds since 2001-01-01 UTC).
SELECT datetime(v.visit_time + 978307200, 'unixepoch') AS visited_utc,
       i.url, v.title, v.load_successful
FROM history_visits v JOIN history_items i ON i.id = v.history_item
ORDER BY v.visit_time DESC LIMIT 100;
```

False-positive note: `moz_places.last_visit_date` and Safari's `history_items` counters are aggregates; only the visit tables carry placeable times. A row present in an aggregate but absent from the visit table means the visit record was removed, not that the visit never happened.

## Class 6 — Extension and permission state

Expected hit: an extension entry with an install time and its permission set, matching an `Extensions\<id>` directory on disk. An entry without a directory, or a directory without an entry, is the anomaly worth explaining.

```bash
# Chromium stores the authoritative extension record in Preferences JSON, not on disk alone.
python3 - <<'PY_BROWSER'
import json
p = "/cases/01/Preferences"
d = json.load(open(p, encoding="utf-8"))
for ext_id, meta in d.get("extensions", {}).get("settings", {}).items():
    print(ext_id, meta.get("path"), meta.get("state"),
          meta.get("install_time"), sorted((meta.get("manifest") or {}).get("permissions") or []))
PY_BROWSER
```

False-positive note: component and policy-installed extensions appear here without a user install event and may lack an `install_time`, and Chrome rewrites `install_time` on profile migration. Read the enterprise policy keys before attributing an extension to the user.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, for every profile analysed, whether the WAL survived acquisition; a report that omits this cannot be reviewed for completeness.
