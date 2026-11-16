# Detection Queries and Telemetry Artifacts

> Sub-skill: [`osquery-extension-and-pack-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Pack, FIM, and extension artifacts owned by this slug. Confirm table and column names with `.schema <table>` on the target osquery version before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `"snapshot": false` with `"removed": true` | High | The query emits transitions, so the log means "what changed" |
| 2 | `file_paths` category present for every FIM query | High | The event publisher has a path scope; without it `file_events` is empty by design |
| 3 | `osquery_flags` showing `enable_file_events` and `disable_events` | High | Publisher state is observable on the endpoint, not assumed |
| 4 | Watchdog denylist entry naming a pack query | High | The query stopped producing data for resource reasons |
| 5 | `osquery_extensions` / `osquery_registry` rows for a custom table | High | The extension registered its table on that endpoint |

## Detection Artifacts

```text
[osquery-extension-and-pack-development:rule-spec] pack queries declare interval + snapshot mode explicitly per change rate
[osquery-extension-and-pack-development:filter-fp] empty file_events = publisher or category missing, not an absence of file changes
[osquery-extension-and-pack-development:correlate] host_identifier + calendar_time joins pack results to a host timeline
```

Verify the publisher state and table shape before trusting any FIM result (Windows PowerShell 5.1):

```powershell
osqueryi --json "SELECT name, value FROM osquery_flags WHERE name IN ('enable_file_events','disable_events');"
osqueryi --json "SELECT * FROM file_events LIMIT 1;"
osqueryi --json ".schema file_events"
```

Run one pack query in isolation and inspect the columns the log will carry:

```powershell
osqueryi --json "SELECT * FROM file_events WHERE category = 'ssh_authorized_keys' LIMIT 5;"
```

Check whether the watchdog has denylisted anything:

```powershell
osqueryi --json "SELECT * FROM osquery_schedule;"
Get-Content "C:\ProgramData\osquery\osqueryd\osqueryd.INFO" |
    Select-String -Pattern 'denylist|watchdog' | Select-Object -Last 20
```

Validate a pack against a test config, where `--ephemeral` keeps the run from touching the host database:

```powershell
osqueryd --ephemeral --disable_extensions=false --config_path .\test-pack.conf --verbose --ephemeral
if ($LASTEXITCODE -ne 0) { Write-Output "pack config rejected"; exit 2 }
```

Custom table smoke test with the extension loaded:

```powershell
osqueryi --extension .\osquery_ext.py --json "SELECT * FROM site_custom_table LIMIT 3;"
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Alert on watchdog denylist entries; a stopped query is silent coverage loss.
- Confirm every FIM query has a matching `file_paths` category in the same config before rollout.
