# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ci-cd-security-gate-and-sarif-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `--help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** SARIF 2.1.0 (`runs[].results[]` with `ruleId`, `level`, `locations[].physicalLocation`, `partialFingerprints`, `baselineState`, `suppressions`) produced by Semgrep CE or CodeQL CLI
- **Validation Gate:** `python -m py_compile sarif_gate.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `semgrep` | `semgrep scan --config p/default --sarif --sarif-output out.sarif .` | Produce SARIF from a ruleset | Cross-platform |
| `semgrep` | `semgrep scan --error` | Exit 1 when findings exist (useful for the scanner step, not the gate) | Cross-platform |
| `semgrep` | `semgrep ci --sarif --sarif-output=semgrep.sarif` | CI-mode scan with SARIF output | Cross-platform |
| `codeql` | `codeql database create <db> --language=<lang> --source-root=. --build-mode=none` | Build the analysis database (`--build-mode=none` for interpreted languages) | Cross-platform |
| `codeql` | `codeql database analyze <db> --format=sarifv2.1.0 --output=out.sarif` | Run queries and emit pinned SARIF | Cross-platform |
| `github/codeql-action/upload-sarif` | `sarif_file`, `category` inputs | Upload SARIF to code scanning, computing fingerprints when source is present | GitHub Actions |
| `git` | `git diff --unified=0 <base>...HEAD` | Zero-context hunks giving exact changed line ranges | Cross-platform |
| Python | `json.loads(sarif)` then iterate `runs[].results[]` | Gate logic over normalized findings | Python 3.11+ |

## Minimal Script

```powershell
semgrep scan --config p/default --sarif --sarif-output .\build\semgrep.sarif .
$scan = $LASTEXITCODE
if ($scan -gt 1) { Write-Output "scanner error (not a finding): $scan"; exit 2 }

python .\sarif_gate.py .\build\semgrep.sarif . origin/main .\baseline\semgrep.sarif
$gate = $LASTEXITCODE
if ($gate -eq 2) { Write-Output "gate could not evaluate input"; exit 2 }
if ($gate -eq 1) { Write-Output "blocking findings introduced by this change" }
exit $gate
```

Exit-code contract: `0` no unbounded new findings on changed lines, `1` at least one such finding, `2` missing or unusable SARIF, unresolvable base ref, or scanner failure.
