# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`syslog-and-cloudtrail-stream-parsers`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — check the provider documentation if a field or envelope differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11 `gzip` + `json` for CloudTrail `.json`/`.json.gz` batches (`Records[]`, `eventTime`, `eventSource`, `eventName`, `userIdentity`, `requestParameters`), positional RFC 5424 header parsing, and escape-aware CEF extension parsing
- **Validation Gate:** `python -m py_compile cloud_audit_parse.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Python `gzip` | `gzip.open(path, "rt", encoding="utf-8")` | Read a compressed CloudTrail object without decompressing to disk | Python 3.11+ |
| Python `json` | `json.load(fh)["Records"]` | Iterate the record array per file | Python 3.11+ |
| Python `datetime` | `datetime.fromisoformat(raw.replace("Z", "+00:00"))` | Parse an offset-bearing `eventTime` | Python 3.11+ |
| `jq` | `jq ".Records" file.json` | List the record array so its length can be reconciled with the parser | Cross-platform |
| `jq` | `jq -r ".Records[].eventName" file.json` | Project event names for a quick diff against the parser | Cross-platform |
| `zcat`/`gzip -dc` | `jq ".Records" <(gzip -dc file.json.gz)` | List records inside a compressed object so the count can be reconciled | Linux/macOS |
| AWS CLI | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging` | Independent retrieval of control-plane events | Cross-platform |
| AWS CLI | `aws cloudtrail describe-trails` | Confirm trail state and selectors | Cross-platform |

## Minimal Script

```powershell
python .\cloud_audit_parse.py .\evidence\cloudtrail\*.json.gz | Set-Content .\build\control-plane.jsonl
$parse = $LASTEXITCODE
if ($parse -eq 2) { Write-Output "unreadable batch or zero records - check gzip and envelope"; exit 2 }

$findings = (Get-Content .\build\control-plane.jsonl -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
Write-Output "parse=$parse control_plane_findings=$findings"
if ($findings -gt 0) { Write-Output "logging-control events present" }
exit $parse
```

Exit-code contract: `0` all batches reconciled with no findings, `1` control-plane finding or rejected records, `2` unreadable/corrupt batch or a zero-record read.
