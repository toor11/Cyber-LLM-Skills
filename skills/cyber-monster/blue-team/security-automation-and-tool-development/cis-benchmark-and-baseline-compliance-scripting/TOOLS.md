# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cis-benchmark-and-baseline-compliance-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `--help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** read-only host queries from Python 3.11 or PowerShell — `sshd -T`, `sysctl -n`, `findmnt`/`mount`, registry and GPO reads — with tri-state JSON results and a stored baseline
- **Validation Gate:** `python -m py_compile cis_audit.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| OpenSSH | `sshd -T` | Dump the effective server configuration | Linux |
| `sysctl` | `sysctl -n kernel.randomize_va_space` | Read an applied kernel parameter | Linux |
| `findmnt` | `findmnt -no OPTIONS /tmp` | Mount options actually in effect | Linux |
| `auditctl` | `auditctl -s` / `auditctl -l` | Audit subsystem status and loaded rules | Linux |
| PowerShell | `Get-ItemProperty -Path 'HKLM:\...'` | Read registry/GPO-backed settings | Windows PowerShell 5.1 |
| PowerShell | `Get-GPOReport -All -ReportType Xml` (with the GPMC module) | Effective policy state as data | Windows |
| `goss`/`syver` | `goss validate -f goss.yaml` | Declarative host assertions with a non-zero exit on failure | Linux |
| `pytest-testinfra` | `pytest --hosts='ssh://host'` | Python-native host assertions (check maintenance status before adopting) | Linux |

## Minimal Script

```powershell
python -m py_compile .\cis_audit.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\cis_audit.py | Set-Content .\baseline\results-after.jsonl
$audit = $LASTEXITCODE

$napp = (Select-String -Path .\baseline\results-after.jsonl -Pattern '"status": "not_applicable"' | Measure-Object).Count
$fail = (Select-String -Path .\baseline\results-after.jsonl -Pattern '"status": "fail"' | Measure-Object).Count
Write-Output "audit_exit=$audit failures=$fail not_applicable=$napp"
exit $audit
```

Exit-code contract: `0` every in-scope control passed, `1` a control failed or errored, `2` the benchmark mapping is missing or the host is unsupported.
