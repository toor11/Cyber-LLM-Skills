# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`osquery-extension-and-pack-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative osquery pack failures, each with the artifact that proves the diagnosis.

## Case 1: FIM pack deployed, zero events ever

- **Surface & Preconditions:** a pack queries `file_events` with a five-minute interval, but the deployed flags never set `enable_file_events` and the config has no `file_paths` section.
- **Root cause & impact:** `file_events` reads from an event publisher that must be both enabled and scoped. The query runs successfully and returns nothing on every host, so the coverage report says "no unauthorized key writes" across the fleet.
- **Verification & fix:** check `SELECT * FROM osquery_flags WHERE name IN ('enable_file_events','disable_events')` on a host and confirm a `file_paths` category exists for the monitored paths; both must be true before the query can produce rows.

## Case 2: A query quietly stopped reporting

- **Surface & Preconditions:** a pack query joins several large tables every 60 seconds on lower-spec endpoints.
- **Root cause & impact:** the watchdog denylists the query for exceeding its memory/CPU budget. No rows appear, and nothing in the log destination distinguishes "never fired" from "was killed".
- **Verification & fix:** inspect `osquery_schedule` and the daemon log for denylist entries; reduce the interval frequency, narrow the join, or split the query. Alert on denylist events.

## Case 3: Log volume spike from a "small" change

- **Surface & Preconditions:** an inventory query is switched to `"snapshot": true` to make dashboards simpler.
- **Root cause & impact:** every host now emits the full table on every interval; volume scales with fleet size times table size, and retention collapses.
- **Verification & fix:** keep differential mode for change tracking and reserve snapshot for genuinely point-in-time needs at a long interval; estimate rows × hosts × intervals before rollout.

## Case 4: Extension loads but returns wrong types

- **Surface & Preconditions:** a Python `TablePlugin` declares `osquery.INTEGER` columns but `generate()` returns strings from a text config file.
- **Root cause & impact:** the declared schema and the returned rows disagree, so downstream SQL comparisons (`WHERE pid > 1000`) silently produce wrong results rather than an error.
- **Verification & fix:** coerce values in `generate()` to match `columns()`, and smoke-test with a query that exercises a comparison on every column type.
