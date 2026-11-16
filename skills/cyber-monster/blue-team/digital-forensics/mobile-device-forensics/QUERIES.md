# Evidence Extraction Artifacts and Queries

> Sub-skill: [`mobile-device-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `mobile-device-forensics`. Each class names the extraction artefact, the parser or query, and the scope fact that must accompany any absence claim. Database queries run read-only with `immutable=1` so a WAL is never replayed into the evidence.

## Class 1 — Acquisition scope record

Expected hit: model, OS build, lock state, extraction class and tool version, written before any content is read. These five fields bound every later claim.

```bash
python -c "import sys; print('\n'.join(f'{k:18}= <acquisition record>' for k in ['model','os_build','lock_state','extraction_class','tool_version']))"
sha256sum ./extraction/*.tar ./extraction/*.zip 2>/dev/null | head
```

False-positive note: an extraction with no recorded lock state cannot be compared with another extraction of the same device, because the difference in content may be entirely a state difference rather than device change.

## Class 2 — Database readability and schema

Expected hit: each SQLite database opens read-only, its table count and row counts are reported, and its schema version is identified. An unreadable database is reported as unreadable, never as empty.

```python
import sqlite3, os
for root, _, files in os.walk("./extraction"):
    for f in files:
        if f.endswith((".db", ".sqlite", ".sqlite3")):
            p = os.path.join(root, f)
            try:
                con = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
                t = [r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")]
                print(p, len(t), "tables", con.execute("PRAGMA user_version").fetchone())
            except sqlite3.DatabaseError as e:
                print("UNREADABLE", p, e)
```

False-positive note: opening a database without `immutable=1` lets SQLite replay and checkpoint the WAL, which mutates evidence. Always use the immutable URI form, and copy the `-wal` and `-shm` files alongside the database.

## Class 3 — Message and call-log recency

Expected hit: newest and oldest timestamps per table, so a boundary is visible as a boundary rather than as a deletion.

```sql
-- Example shape for a message table; substitute the schema your app version uses.
SELECT MIN(date) AS oldest, MAX(date) AS newest, COUNT(*) AS rows
FROM message
WHERE date IS NOT NULL;
```

False-positive note: a newest row days before the seizure is consistent with app retention, a device that stopped syncing, or a second device taking over. Compare against the call log and notification history before describing a gap as deletion.

## Class 4 — Media file identity and capture time

Expected hit: files whose embedded capture time and filesystem creation time both exist, with the delta shown.

```bash
exiftool -T -FileName -DateTimeOriginal -CreateDate -FileModifyDate -r ./extraction/media 2>/dev/null | head -20
```

False-positive note: camera imports, messaging apps and cloud downloads routinely write files hours after capture. A trail in creation time is normal and is not timestomping unless the embedded metadata has also been rewritten.

## Class 5 — Deleted-content recovery from unallocated space

Expected hit: carved fragments that are absent from the live database but present in the image — only obtainable from a physical or full file system extraction.

```bash
tsk_recover -e -o 0 ./physical.dd ./recovered 2>/dev/null
grep -a -c "CREATE TABLE" ./recovered/*.db 2>/dev/null | head
```

False-positive note: continuous TRIM and background garbage collection can erase deleted content within hours on modern devices. Absence from unallocated space is a maintenance outcome and does not prove a wipe; conversely, recovered fragments prove the content existed, not who deleted it.

## Class 6 — Device logs and lock-state evidence

Expected hit: system log entries showing unlock attempts, boot events and app lifecycle around the incident window.

```bash
find ./extraction -iname "*log*" -o -iname "*diagnostic*" | head -20
grep -a -i "unlock\|authenticat" ./extraction/logs/*.log 2>/dev/null | head -20
```

False-positive note: log bundles are often the only data class available from a BFU device, and their presence can mislead an analyst into treating the extraction as more complete than it is. State the class before citing log content as evidence of user activity.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the extraction class, lock state and tool version beside every finding derived from a mobile image.
