# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`purple-team-telemetry-validation-harnesses`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** lab-scoped Python 3.11 runner with a bounded poll loop over a SIEM/EDR query API, and an ATT&CK Navigator layer 4.5 export (`versions.layer`, `domain`, `techniques[]`)
- **Validation Gate:** `python -m py_compile purple_harness.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Python `time` | `time.monotonic()` around the poll loop | Measure latency without wall-clock drift | Python 3.11+ |
| Python `uuid` | `uuid.uuid4().hex[:12]` | Unique correlation id per case | Python 3.11+ |
| Python | `try/finally` around case execution | Guarantee cleanup on failure | Python 3.11+ |
| SIEM query API | `POST /api/query` with a correlation-id filter | Confirm the event was collected | HTTP |
| `mitreattack-python` | `from mitreattack.navlayers import Layer` → `Layer().from_file(path)` | Validate or upgrade a layer file | Python |
| Navigator schema | `versions.layer: "4.5"`, `domain`, `techniques[].techniqueID` | Importable layer requirements | JSON |

## Minimal Script

```powershell
python -m py_compile .\purple_harness.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\purple_harness.py 1> .\build\verdicts.jsonl 2> .\build\layer.json
$run = $LASTEXITCODE

$gaps = (Select-String -Path .\build\verdicts.jsonl -Pattern '"fired": false' | Measure-Object).Count
$cleanup = (Select-String -Path .\build\verdicts.jsonl -Pattern '"cleanup_ok": true' | Measure-Object).Count
Write-Output "gaps=$gaps cleanup_ok=$cleanup exit=$run"
if ($run -eq 2) { Write-Output "cleanup failed: lab state unknown"; exit 2 }
exit $run
```

Exit-code contract: `0` every case collected, fired, field-complete, with cleanup confirmed; `1` at least one coverage gap; `2` cleanup or environment validation failed.
