# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ocsf-and-ecs-log-normalizer-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `vector --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** OCSF 1.8 event classes (`class_uid`, `category_uid`, `activity_id`, `severity_id`) or ECS 9.x (`@timestamp`, `event.category`, `event.type`, `event.kind`), implemented in Vector VRL or Python 3.11
- **Validation Gate:** `vector validate --no-environment vector.toml; python -m py_compile normalize_events.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `vector` | `vector validate --no-environment vector.toml` | Type-check the config and every VRL program without touching a live environment | Cross-platform |
| `vector` | `vector --config vector.toml --quiet` | Run the pipeline | Cross-platform |
| VRL | `parsed, err = parse_json(.message)` | Fallible parse with an inspectable error instead of an abort | Engine |
| VRL | `object!(parsed)` | Assert the parsed value is a map before replacing the event | Engine |
| VRL | `parse_timestamp(.ts, format: "%Y-%m-%dT%H:%M:%S%z")` | Parse an offset-bearing timestamp into a real timestamp type | Engine |
| VRL | `reroute_dropped = true` (transform option) | Send aborted events to `<transform>.dropped` for a dead-letter sink | Engine |
| Python | `datetime.fromisoformat(text.replace("Z", "+00:00"))` | Parse ISO-8601 with an explicit offset; rejects naive values when checked | Python >= 3.11 |
| Python | `json.dumps(..., flush=True)` | Deterministic one-record-per-line output for streaming consumers | Python >= 3.11 |
| OCSF | `class_uid` / `category_uid` enums per schema version | Class identity and its parent category | Schema |
| ECS | `event.category`, `event.type`, `event.kind` | Semantic triple for path-based destinations | Schema |

## Minimal Script

```powershell
# Vector installs as a packaged binary (MSI/zip on Windows), not via pip.
vector --version
vector validate --no-environment .\vector.toml
$valid = $LASTEXITCODE
if ($valid -ne 0) { Write-Output "config/VRL invalid: $valid"; exit 2 }
python -m py_compile .\normalize_events.py
python .\normalize_events.py .\fixtures\mixed.jsonl .\out\deadletter.jsonl
$norm = $LASTEXITCODE
$dead = (Select-String -Path .\out\deadletter.jsonl -Pattern '"error"').Count
Write-Output "normalizer exit=$norm dead_lettered=$dead"
```

Exit-code contract: `0` all fixtures classified with correct UTC instants and exactly the expected dead letters, `1` mapping or differential failure, `2` invalid config, missing schema file, or missing fixture.
