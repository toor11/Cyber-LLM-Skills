# Detection Queries and Telemetry Artifacts

> Sub-skill: [`soar-playbook-and-webhook-connector-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Receiver and execution artifacts owned by this slug. Every automated containment action must leave an audit record; the shapes below are what that record should contain.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | HMAC verified over raw body with `compare_digest` | High | The request is authentic and unmodified |
| 2 | Timestamp skew check rejecting an old request | High | A captured request cannot be replayed later |
| 3 | Idempotency key already present in the store | High | Duplicate delivery will not re-execute the action |
| 4 | Protected-asset refusal record | High | Blast-radius policy was enforced server-side |
| 5 | Approval approver + timestamp in the audit record | High | A destructive action had human authorization |

## Detection Artifacts

```text
[soar-playbook-and-webhook-connector-development:rule-spec] verify HMAC over raw bytes, then skew, then idempotency, then scope, then approval
[soar-playbook-and-webhook-connector-development:filter-fp] a retried delivery is not a second incident; dedup by idempotency key
[soar-playbook-and-webhook-connector-development:correlate] audit record keyed by request id ties decision, actor, and target together
```

Verifying a signature the same way the receiver does, so a sender-side fix can be tested independently (Windows PowerShell 5.1):

```powershell
$body = '{"host":"web01","action":"isolate","idempotency_key":"abc-123"}'
$ts   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
$key  = [Text.Encoding]::UTF8.GetBytes("replace-from-secret-store")
$mac  = [Security.Cryptography.HMACSHA256]::new($key)
$data = [Text.Encoding]::UTF8.GetBytes("$ts.$body")
$sig  = ($mac.ComputeHash($data) | ForEach-Object { $_.ToString("x2") }) -join ""
Write-Output "timestamp=$ts signature=$sig"
```

Replay and dedup behaviour, exercised as a fixture set rather than in production:

```text
[soar-playbook-and-webhook-connector-development:fixture] same key twice -> first executes, second returns duplicate
[soar-playbook-and-webhook-connector-development:fixture] same body, timestamp older than window -> reject
[soar-playbook-and-webhook-connector-development:fixture] host dc01 -> refuse, reason protected_asset
[soar-playbook-and-webhook-connector-development:fixture] isolate without approval -> refuse, reason missing_approval
```

Confirm the connector's refusal path does not call the containment API at all, by pointing the API base URL at a local sink during tests:

```powershell
$env:EDR_API_BASE = "http://127.0.0.1:8080"
python .\soar_connector.py $sig $ts < .\fixtures\protected_dc01.json
if ($LASTEXITCODE -ne 1) { Write-Output "expected policy refusal exit 1"; exit 1 }
```

Audit record shape, one line per decision including refusals:

```json
{"request_id": "9f1c", "decision": "refuse", "reason": "protected_asset", "host": "dc01", "actor": "soar-runner", "approver": null, "ts": "2026-11-14T18:40:00Z"}
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Run every new playbook in dry-run against a staging tenant before enabling execution.
- Keep the protected-asset list in configuration under change control, and audit changes to it like firewall rules.
