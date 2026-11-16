# Detection Queries and Telemetry Artifacts

> Sub-skill: [`suricata-lua-and-rule-qa-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Load-gate, lint, and PCAP-regression artifacts owned by this slug. Verify flag availability against `suricata --build-info` and `suricata-verify --help` on the installed release.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `suricata -T` exit status | High | The rule set loads against the real config; unmet `requires` and syntax faults surface here |
| 2 | `eve.json` `event_type: alert` with `alert.signature_id` | High | Which `sid` fired, so a differential attributes change to one rule |
| 3 | `flowbits:isset` without a matching `flowbits:set` in the same rule file | High | A stateful rule that can never fire; detectable before deployment |
| 4 | Duplicate `sid` across rule files | High | Rule-shadowing; only one definition survives engine load |
| 5 | Lua script terminated without a Lua error | Medium | The sandbox instruction limit stopped it, not a logic fault |

## Detection Artifacts

```text
[suricata-lua-and-rule-qa-tooling:rule-spec] sid unique per ruleset, rev incremented on every content change
[suricata-lua-and-rule-qa-tooling:filter-fp] benign control PCAP must yield zero alerts for the same sid
[suricata-lua-and-rule-qa-tooling:correlate] eve.json alert.signature_id ties an alert back to one rule revision
```

Load gate plus a single-fixture replay (Windows PowerShell 5.1):

```powershell
Set-Location C:\suricata\rules
suricata -T -S .\local.rules -c C:\suricata\suricata.yaml
$load = $LASTEXITCODE
if ($load -ne 0) { Write-Output "rule set failed to load: $load"; exit 2 }
suricata -r .\fixtures\malicious.pcap -S .\local.rules -c C:\suricata\suricata.yaml -l .\out-positive
Select-String -Path .\out-positive\eve.json -Pattern '"signature_id":1000201'
```

Static property lint over the rule text (unpaired flowbits, duplicate sids):

```powershell
$rules = Get-Content .\local.rules | Where-Object { $_ -match '^\s*alert ' }
$sids = $rules | ForEach-Object { [regex]::Match($_, 'sid:(\d+)').Groups[1].Value }
$sids | Group-Object | Where-Object Count -gt 1 | ForEach-Object { Write-Output "duplicate sid: $($_.Name)" }
$sets = @($rules | Where-Object { $_ -match 'flowbits:set,([A-Za-z0-9_.]+)' })
```

`suricata-verify` case asserting the alert count for one rule:

```yaml
checks:
  - filter:
      count: 1
      match:
        event_type: alert
        alert.signature_id: 1000201
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Re-run the differential whenever `fast_pattern` moves, even if the intent was purely performance.
- Re-test every `lua` rule after a Suricata minor-version bump, since the sandbox and Lua version are part of the runtime contract.
