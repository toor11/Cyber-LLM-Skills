# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`edr-api-triage-and-containment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented endpoints or permission names — confirm against the vendor's current API reference.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `falconpy` (`Hosts` for lookup, `RealTimeResponse` for `init_session`/`batch_init_sessions`) or Microsoft Defender for Endpoint REST via `requests` (`POST /api/machines/{id}/isolate` with `Comment` and `IsolationType`)
- **Validation Gate:** `python -m py_compile edr_triage.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `falconpy` | `Hosts(client_id=..., client_secret=...).query_devices_by_filter(filter="hostname:'x'")` | Resolve a hostname to device ids | Python |
| `falconpy` | `RealTimeResponse(...).init_session(device_id=...)` | Open an RTR session before any RTR command | Python |
| `falconpy` | `RealTimeResponse(...).batch_init_sessions(host_ids=[...])` | Open sessions across many hosts | Python |
| Defender REST | `GET /api/machines?$filter=computerDnsName eq '<host>'` | Resolve hostname and read `isIsolated` | HTTP |
| Defender REST | `POST /api/machines/{id}/isolate` with `{"Comment": "...", "IsolationType": "Full"}` | Contain a device (`Full`, `Selective`, `UnManagedDevice`) | HTTP |
| Defender REST | `POST /api/machines/{id}/unisolate` | Release containment | HTTP |
| Python `requests` | `requests.post(..., timeout=20)` plus exponential backoff on 429/5xx | Transport with an explicit timeout | Python 3.11+ |
| Python `argparse` | `--dry-run`-style flag defaulting to read-only | Keep the safe path the default | Python 3.11+ |

## Minimal Script

```powershell
python -m py_compile .\edr_triage.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\edr_triage.py --hostname web01.example.internal --action isolate 2>&1 |
    Tee-Object -FilePath .\build\edr-audit.jsonl
$dry = $LASTEXITCODE
if ($dry -ne 0) { Write-Output "dry-run refusal or resolve failure: $dry"; exit $dry }

Write-Output "dry run complete; supply --execute with an approval token to act"
```

Exit-code contract: `0` requested state confirmed (or a dry-run plan produced), `1` policy refusal (protected asset, missing approval, already in state, unresolved host), `2` authentication or transport failure after the retry budget.
