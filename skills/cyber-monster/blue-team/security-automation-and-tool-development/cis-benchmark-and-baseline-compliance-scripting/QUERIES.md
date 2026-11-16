# Detection Queries and Telemetry Artifacts

> Sub-skill: [`cis-benchmark-and-baseline-compliance-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Read-only compliance artifacts owned by this slug. Every result row carries the command that produced the observation.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `sshd -T` output rather than the config file | High | The effective SSH value, after all overrides |
| 2 | `sysctl -n <key>` rather than a `/proc` path | High | The applied kernel parameter |
| 3 | `not_applicable` with a reason | High | The control was not silently counted as compliant |
| 4 | Benchmark name and version in the report | High | The findings are attributable to a specific control set |
| 5 | Host state unchanged across the audit | High | The auditor is genuinely read-only |

## Detection Artifacts

```text
[cis-benchmark-and-baseline-compliance-scripting:rule-spec] effective runtime values, tri-state results, benchmark version recorded
[cis-benchmark-and-baseline-compliance-scripting:filter-fp] an unevaluable control is not a pass
[cis-benchmark-and-baseline-compliance-scripting:correlate] control id + observed value + command reproduces the judgement
```

Effective SSH configuration, which resolves precedence for you (Windows PowerShell 5.1 via SSH or WSL):

```powershell
wsl -u root sshd -T | Select-String -Pattern '^permitrootlogin|^passwordauthentication|^permitemptypasswords'
```

Kernel parameters and filesystem flags as applied, not as written:

```powershell
wsl -u root sysctl -n kernel.randomize_va_space
wsl -u root findmnt -no OPTIONS /tmp
wsl -u root mount | Select-String -Pattern ' /tmp '
```

Audit trail check, confirming the run made no state change:

```powershell
wsl -u root audctl 2>$null
wsl -u root ausearch -ts recent -m SYSCALL | Select-String -Pattern 'proctitle' | Select-Object -First 5
```

Windows registry read for a GPO-backed control, without any write:

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue |
    Select-Object NoAutoUpdate, AUOptions
```

Drift comparison between two stored result sets:

```powershell
$before = Get-Content .\baseline\results-before.jsonl | ConvertFrom-Json
$after  = Get-Content .\baseline\results-after.jsonl  | ConvertFrom-Json
Compare-Object $before $after -Property control, status |
    Where-Object SideIndicator -eq '<=' |
    Select-Object control, status
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Store the baseline result set in version control so drift is computed against a known reference.
- Re-map the control table whenever the benchmark version changes; do not assume numbering is stable.
- Assert in CI that the auditor performs no writes: run it under a read-only account and fail if the run errors on permissions instead of reporting `not_applicable`.
