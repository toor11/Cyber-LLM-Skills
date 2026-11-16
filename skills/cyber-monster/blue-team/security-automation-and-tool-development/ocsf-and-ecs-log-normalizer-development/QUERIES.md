# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ocsf-and-ecs-log-normalizer-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Normalization and validation artifacts owned by this slug. Confirm `class_uid` values against the target OCSF schema version and `event.*` values against the destination ECS major before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `class_uid` with a category that matches its class (e.g. `3004` → `3`) | High | The classifier emitted a real, self-consistent OCSF identity |
| 2 | `@timestamp` ending in `Z` or carrying an offset | High | The instant is unambiguous; a naive value would land in the wrong hour |
| 3 | Dead-letter line count rising while input volume is flat | High | The parser stopped understanding a feed, independent of collection |
| 4 | `event.category` / `event.type` / `event.kind` all populated | Medium | The ECS triple is complete enough for standard detection queries |
| 5 | `unmapped.original` (or equivalent) present on every record | Medium | The raw event survives normalization, so a mapping error is replayable |

## Detection Artifacts

```text
[ocsf-and-ecs-log-normalizer-development:rule-spec] class_uid + category_uid + activity_id + severity_id + time are mandatory
[ocsf-and-ecs-log-normalizer-development:filter-fp] refuse naive local timestamps instead of assuming the collector's timezone
[ocsf-and-ecs-log-normalizer-development:correlate] dead-letter growth rate per feed is the pipeline health signal
```

Vector pipeline with explicit fallible parsing and a dead-letter sink (Windows PowerShell 5.1 validation):

```toml
[transforms.parse_vendor]
type = "remap"
inputs = ["vendor_raw"]
reroute_dropped = true
source = '''
  parsed, err = parse_json(.message)
  if err != null {
    log("unparseable vendor line", level: "warn")
    abort
  }
  . = object!(parsed)
  .class_uid = 3002
  .category_uid = 3
  .severity_id = to_int(.severity_id) ?? 0
  .time = parse_timestamp(.ts, format: "%Y-%m-%dT%H:%M:%S%z") ?? now()
'''

[sinks.dead_letter]
type = "file"
inputs = ["parse_vendor.dropped"]
path = "C:/logs/vector/normalizer-deadletter.jsonl"
encoding.codec = "json"
```

```powershell
vector validate --no-environment .\vector.toml
if ($LASTEXITCODE -ne 0) { Write-Output "VRL type-check failed"; exit 2 }
python -m py_compile .\normalize_events.py
Get-Content .\fixtures\mixed.jsonl | ForEach-Object { $_ } | Measure-Object -Line
Select-String -Path .\out\deadletter.jsonl -Pattern '"raw"' | Measure-Object | Select-Object -ExpandProperty Count
```

Fixture assertions: one well-formed record normalizes with a UTC instant, a naive-timestamp record is dead-lettered rather than defaulted, and a malformed JSON line keeps its original bytes.

```json
{"ts": "2026-11-14T18:40:00+03:00", "user": "alice", "result": "success", "src_ip": "203.0.113.9"}
{"ts": "2026-11-14 18:40:00", "user": "bob", "result": "failure", "src_ip": "203.0.113.10"}
{"ts": "2026-11-14T18:41:00Z", "user": }}
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Alert on dead-letter growth per feed; a flat input rate with rising dead letters is a silent coverage loss.
- Pin the destination schema version and re-run the fixture set when either schema moves a minor version.
