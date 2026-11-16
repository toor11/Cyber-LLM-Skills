# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-and-modsecurity-crs-rule-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `go-ftw run --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** OWASP CRS 4.x SecLang rules on ModSecurity (`SecRule`, `setvar:tx.anomaly_score_pl*`, `ctl:ruleRemoveTargetById`), regression-tested with `go-ftw` against a `DetectionOnly` WAF
- **Validation Gate:** `go-ftw check -d tests/regression/tests` then `go-ftw run -d tests/regression/tests --config .ftw.apache.yaml`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `go-ftw` | `./go-ftw run --config .ftw.apache.yaml -d tests/regression/tests/` | Run the regression suite against a WAF | Cross-platform |
| `go-ftw` | `./go-ftw check -d tests/regression/tests` | Validate test files without executing | Cross-platform |
| `go-ftw` | `-i "<regex>"` / `-e "<regex>"` | Include or exclude tests by id or title | Cross-platform |
| `go-ftw` | `--fail-fast` | Stop on the first failure | Cross-platform |
| ModSecurity | `SecRule ... "id:N,phase:2,pass,nolog,ctl:ruleRemoveTargetById=<id>;ARGS:<name>"` | Scoped exclusion | Engine |
| ModSecurity | `setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'` | Anomaly increment in a detection rule | Engine |
| CRS | `tx.blocking_paranoia_level`, `tx.detection_paranoia_level` | CRS 4 paranoia configuration | Configuration |
| CRS | `tx.inbound_anomaly_score_threshold` | Blocking threshold checked by the evaluation rule | Configuration |

## Minimal Script

```powershell
# Run on the WAF host or inside its container.
go-ftw check -d .\tests\regression\tests
if ($LASTEXITCODE -ne 0) { Write-Output "test files invalid"; exit 2 }

go-ftw run --config .\.ftw.apache.yaml -d .\tests\regression\tests -i "1000100|942100" --fail-fast
$suite = $LASTEXITCODE
Write-Output "regression_exit=$suite"
if ($suite -ne 0) { Write-Output "regression failure: exclusion may have opened a bypass" }
exit $suite
```

Exit-code contract: `0` all included cases pass (legitimate request allowed, attack still blocked), `1` a case failed, `2` test files or config invalid.
