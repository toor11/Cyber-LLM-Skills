# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`custom-secret-scanner-detector-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `gitleaks detect --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Gitleaks 8.x TOML configuration (`[[rules]]` with `id`, `regex`, `secretGroup`, `entropy`, `keywords`, `[[rules.allowlists]]` with `regexTarget`) plus a Python 3.11 streamer for history and archive cases
- **Validation Gate:** `python -m py_compile secret_scan.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `gitleaks` | `gitleaks detect --source <path> --config gitleaks.toml` | Scan a repository or directory for secrets | Cross-platform |
| `gitleaks` | `gitleaks detect --source <path> --no-git` | Scan files without Git history | Cross-platform |
| `gitleaks` | `gitleaks detect --report-format json --report-path out.json` | Machine-readable findings for a gate | Cross-platform |
| `gitleaks` | `gitleaks dir <path> --config gitleaks.toml` | Scan a plain directory tree | Cross-platform |
| `gitleaks` | `--ignore-gitleaks-allow` | Override inline `gitleaks:allow` comments when auditing them | Cross-platform |
| TOML config | `entropy`, `secretGroup`, `keywords`, `regex`, `path` | Rule stages: entropy floor, captured group, prefilter, pattern, path-only rule | Configuration |
| TOML config | `[[rules.allowlists]]` with `condition`, `paths`, `regexes`, `regexTarget`, `stopwords` | Per-rule exclusions scoped to secret, match, or line | Configuration |
| Python `hashlib` | `hashlib.sha256(salt + secret).hexdigest()[:16]` | Redacted fingerprint for reports | Python 3.11+ |
| Python `subprocess` | `git log -p --no-color --all` | Stream full history diffs for custom scanning | Cross-platform |
| Python `math` | `-sum((c/n) * math.log2(c/n) ...)` | Shannon entropy floor in the custom scanner | Python 3.11+ |

## Minimal Script

```powershell
gitleaks version
gitleaks detect --source . --no-git --config .\gitleaks.toml --report-format json --report-path .\build\secrets-tree.json
$tree = $LASTEXITCODE
if ($tree -gt 1) { Write-Output "gitleaks config or read error"; exit 2 }

python .\secret_scan.py | Set-Content .\build\secrets-history.jsonl
$hist = $LASTEXITCODE

$leak = Select-String -Path .\build\secrets-history.jsonl -Pattern 'svc_live_' -SimpleMatch -Quiet
if ($leak) { Write-Output "raw secret present in output"; exit 1 }
Write-Output "tree=$tree history=$hist"
```

Exit-code contract: `0` no findings, `1` findings present (or a redaction failure, which is always blocking), `2` config parse error or unreadable target.
