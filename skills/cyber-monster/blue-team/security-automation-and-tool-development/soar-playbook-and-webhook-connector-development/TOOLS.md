# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`soar-playbook-and-webhook-connector-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented behaviour — confirm against the platform's webhook documentation before deployment.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11 `hmac`/`hashlib` over the raw request body, an idempotency store keyed on a caller-supplied key, `requests` with exponential backoff and jitter, and an append-only audit record
- **Validation Gate:** `python -m py_compile soar_connector.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Python `hmac` | `hmac.new(key, msg, hashlib.sha256).hexdigest()` | Compute the expected signature | Python 3.11+ |
| Python `hmac` | `hmac.compare_digest(a, b)` | Constant-time signature comparison | Python 3.11+ |
| Python `hashlib` | `hashlib.sha256(...)` | Hash primitive for the HMAC | Python 3.11+ |
| Python `http.server` | `BaseHTTPRequestHandler` with `self.rfile.read(int(self.headers["Content-Length"]))` | Minimal receiver that reads the raw body | Python 3.11+ |
| `requests` | `requests.post(url, json=body, headers=..., timeout=10)` | Outbound containment call with an explicit timeout | Python 3.11+ |
| Python `time` | `time.sleep(delay + random.uniform(0, delay / 2))` | Backoff with jitter | Python 3.11+ |
| Python `json` | `json.dumps({...})` one line per decision | Append-only audit records | Python 3.11+ |
| EDR REST | `POST /api/machines/{id}/isolate` with `Comment` and `IsolationType` (`Full`/`Selective`) | Vendor containment action this playbook invokes | HTTP |

## Minimal Script

```powershell
$body = Get-Content .\fixtures\isolate_web01.json -Raw
$ts   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
$key  = [Text.Encoding]::UTF8.GetBytes("replace-from-secret-store")
$mac  = [Security.Cryptography.HMACSHA256]::new($key)
$sig  = (($mac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$ts.$body"))) | ForEach-Object { $_.ToString("x2") }) -join ""

$body | python .\soar_connector.py $sig $ts | Add-Content .\build\audit.jsonl
$run = $LASTEXITCODE
python -m py_compile .\soar_connector.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }
Write-Output "connector exit=$run"
exit $run
```

Exit-code contract: `0` authentic, unique, approved, in-scope, and executed (or a duplicate correctly short-circuited), `1` policy refusal (protected asset or missing approval), `2` unverifiable request or transport failure after the retry budget.
