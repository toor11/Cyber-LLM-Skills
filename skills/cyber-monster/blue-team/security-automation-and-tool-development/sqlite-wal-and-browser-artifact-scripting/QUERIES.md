# Detection Queries and Telemetry Artifacts

> Sub-skill: [`sqlite-wal-and-browser-artifact-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Snapshot, hash-manifest, and extraction artifacts owned by this slug. Confirm table names against the browser or application build on the evidence host before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Identical SHA-256 manifest before and after the query | High | The evidence files were read, not modified |
| 2 | `-wal` present in the temp snapshot directory | High | Un-checkpointed commits will be replayed rather than omitted |
| 3 | `GROUP BY u.url` with `MAX(v.visit_time)` | High | Distinct recent sites, not repeat navigations of one page |
| 4 | Converted timestamp inside the plausible acquisition window | High | Integer WebKit epoch math is correct; 1601 or a future year indicates a bad value |
| 5 | `PermissionError [WinError 32]` on temp cleanup | Medium | A connection was left open; the handle, not the evidence, is the problem |

## Detection Artifacts

```text
[sqlite-wal-and-browser-artifact-scripting:rule-spec] copy DB + -wal + -journal to temp, then open the copy read-only
[sqlite-wal-and-browser-artifact-scripting:filter-fp] immutable=1 with live sidecars hides un-checkpointed visits -> never use it here
[sqlite-wal-and-browser-artifact-scripting:correlate] visit_time (WebKit µs) -> UTC, grouped per URL for distinct-site reporting
```

Snapshot plus hash gate in Windows PowerShell 5.1:

```powershell
$src = "C:\evidence\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default"
$work = "C:\work\sqlite-snapshot"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Get-ChildItem -Path $src -Filter "History*" | ForEach-Object {
    Get-FileHash $_.FullName -Algorithm SHA256 | Select-Object Hash, Path
} | Format-Table -AutoSize
Copy-Item "$src\History","$src\History-wal","$src\History-journal" -Destination $work -ErrorAction SilentlyContinue
python .\parse_browser_db.py "$work\History" | Set-Content "$work\recent-urls.json"
```

Re-hash after extraction; the manifest must be identical to the pre-extraction output:

```powershell
Get-ChildItem -Path $src -Filter "History*" |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "{0}  {1}" -f $_.Hash, (Split-Path $_.Path -Leaf) }
```

Distinct-site query executed against the snapshot copy only:

```sql
SELECT MAX(v.visit_time) AS last_us,
       u.url,
       COALESCE(u.title, '') AS title
FROM visits v
JOIN urls u ON u.id = v.url
WHERE v.visit_time > 0 AND u.url <> ''
GROUP BY u.url
ORDER BY last_us DESC, u.url ASC
LIMIT 50;
```

Firefox equivalent, for schema-family confirmation (different table names, same discipline):

```sql
SELECT MAX(h.visit_date) AS last_us, p.url, COALESCE(p.title, '') AS title
FROM moz_historyvisits h
JOIN moz_places p ON p.id = h.place_id
WHERE h.visit_date > 0
GROUP BY p.url
ORDER BY last_us DESC
LIMIT 50;
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Store the pre- and post-extraction manifests with the derived output; the report is only admissible alongside proof the source did not change.
- Never write derived output into the evidence directory; keep the source volume read-only where the platform allows it.
