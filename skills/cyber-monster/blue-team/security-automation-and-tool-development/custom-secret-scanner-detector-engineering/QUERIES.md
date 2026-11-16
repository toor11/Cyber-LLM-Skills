# Detection Queries and Telemetry Artifacts

> Sub-skill: [`custom-secret-scanner-detector-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Detector and scan artifacts owned by this slug. Output from this skill is itself sensitive: never paste a raw secret into a ticket, and always record the redacted fingerprint instead.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Rule contains `keywords` + `regex` + `secretGroup` + `entropy` | High | The detector has all three false-positive stages, not just a pattern |
| 2 | Placeholder fixture stays silent while the real-shape fixture matches | High | The entropy floor and structure discriminate, not just the regex |
| 3 | Finding carries `secret_sha256_16` and no plaintext | High | The report can be shared without becoming a second leak |
| 4 | `allowlists` entry with `paths` or `regexTarget = "line"` | High | Exclusions are scoped to fixtures/docs rather than to the whole rule |
| 5 | Same fingerprint appears in multiple commits | Medium | Duplicate history hits; report the earliest introducing commit |

## Detection Artifacts

```text
[custom-secret-scanner-detector-engineering:rule-spec] prefix anchor + keyword prefilter + entropy floor + scoped allowlist
[custom-secret-scanner-detector-engineering:filter-fp] placeholder in the same shape must not match
[custom-secret-scanner-detector-engineering:correlate] salted sha256 of the secret correlates findings across runs without exposing it
```

Gitleaks rule with all three stages and a scoped allowlist:

```toml
[[rules]]
id = "internal-service-token"
description = "Internal service token issued by the platform control plane"
regex = '''\bsvc_(?:live|test)_([0-9A-Za-z]{32,48})\b'''
secretGroup = 1
entropy = 3.5
keywords = ["svc_live", "svc_test"]
tags = ["credential", "internal"]

[[rules.allowlists]]
description = "documented placeholders in tests and docs"
condition = "OR"
paths = ['''(^|/)(tests?|fixtures?|docs?)/''']
regexes = ['''svc_(live|test)_0{8}''']
```

Run against the working tree and against full history (Windows PowerShell 5.1):

```powershell
gitleaks detect --source . --no-git --config .\gitleaks.toml --report-format json --report-path .\build\secrets-tree.json
$tree = $LASTEXITCODE
gitleaks detect --source . --config .\gitleaks.toml --report-format json --report-path .\build\secrets-history.json
$history = $LASTEXITCODE
Write-Output "tree=$tree history=$history"
```

Redaction self-check: the report must not contain the literal secret used in the fixture.

```powershell
$fixture = "svc_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
$hit = Select-String -Path .\build\secrets-history.json -Pattern $fixture -SimpleMatch -Quiet
if ($hit) { Write-Output "LEAK: report contains the raw secret"; exit 1 }
```

Fingerprint a confirmed finding for the ticket without exposing the value:

```powershell
$secret = Read-Host -AsSecureString "secret"
$plain  = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret))
$hash = [BitConverter]::ToString(
          [Security.Cryptography.SHA256]::Create().ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($plain))).Replace("-","").ToLower().Substring(0,16)
Write-Output "fingerprint=$hash length=$($plain.Length)"
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Scan full history once at onboarding, then scan diffs; a history-only scan hides new leaks until the next full run.
- Restrict the report artifact's access: a fingerprint list is low-risk, but any tool that dumps matched context is not.
