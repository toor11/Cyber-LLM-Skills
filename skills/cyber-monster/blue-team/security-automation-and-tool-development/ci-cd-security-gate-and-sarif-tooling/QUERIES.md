# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ci-cd-security-gate-and-sarif-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

SARIF ingestion and PR-gate artifacts owned by this slug. Confirm SARIF fields against the producing scanner version before deployment; the 2.1.0 object set is stable but producers populate it unevenly.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `partialFingerprints.primaryLocationLineHash` present | High | Findings can be matched across runs; without it every run looks new |
| 2 | `baselineState` == `new` | High | The finding was introduced after the baseline, not inherited |
| 3 | `suppressions[].status` == `underReview` or `rejected` | High | The waiver is not in force; treating it as suppression is a bypass |
| 4 | `physicalLocation.region.startLine` intersecting a changed hunk | High | The PR touched the code the finding sits on |
| 5 | Distinct exit codes for findings vs environment failure | High | A crashed scanner is never reported as a clean PR |

## Detection Artifacts

```text
[ci-cd-security-gate-and-sarif-tooling:rule-spec] block only when baselineState=new AND line in changed hunk AND no live waiver
[ci-cd-security-gate-and-sarif-tooling:filter-fp] absent partialFingerprints makes every rerun "new" -> generate fingerprints, do not lower severity
[ci-cd-security-gate-and-sarif-tooling:correlate] fingerprint + ruleId identifies one finding across three runs
```

Producing SARIF from each scanner, then gating (Windows PowerShell 5.1):

```powershell
semgrep scan --config p/default --sarif --sarif-output .\build\semgrep.sarif .
if ($LASTEXITCODE -gt 1) { Write-Output "semgrep failed outright"; exit 2 }

codeql database create .\build\db --language=javascript --source-root=. --build-mode=none
codeql database analyze .\build\db --format=sarifv2.1.0 --output .\build\codeql.sarif
if ($LASTEXITCODE -ne 0) { Write-Output "codeql analyze failed"; exit 2 }

python .\sarif_gate.py .\build\semgrep.sarif . main .\baseline\semgrep.sarif
$gate = $LASTEXITCODE
Write-Output "gate exit=$gate"
exit $gate
```

Changed-line ranges the gate intersects against:

```powershell
git diff --unified=0 origin/main...HEAD -- "*.py","*.js","*.ts" |
    Select-String -Pattern '^\+\+\+ b/|^@@ '
```

Minimal SARIF result carrying the three fields the gate depends on:

```json
{
  "ruleId": "python.lang.security.audit.eval-detected",
  "level": "error",
  "message": {"text": "Detected use of eval"},
  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/handler.py"},
                                       "region": {"startLine": 42, "endLine": 42}}}],
  "partialFingerprints": {"primaryLocationLineHash": "3f9a1c2b7d"},
  "baselineState": "new",
  "suppressions": [{"kind": "external", "status": "accepted",
                    "properties": {"expires_at": "2027-01-31", "reason": "legacy parser"}}]
}
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Record the base ref used for the diff in the job output; an unresolvable base silently changes the verdict.
- Fail the job when a waiver has no `expires_at`; a permanent waiver is an undocumented bypass.
- Keep the baseline SARIF in version control so `baselineState` is reproducible per commit.
- Store the gate's own exit code separately from each scanner's exit code in the job summary.
