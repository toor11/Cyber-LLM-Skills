# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`velociraptor-vql-artifact-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags or plugin names — run `velociraptor.exe --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Velociraptor artifact YAML (`name`, `description`, typed `parameters`, `sources[].query`, `resources` with `timeout`/`ops_per_second`/`cpu_limit`/`iops_limit`/`max_rows`/`max_upload_bytes`) and VQL plugins (`glob`, `parse_evtx`, `parse_mft`, `parse_prefetch`, `parse_pe`, `yara`, `read_reg_key`)
- **Validation Gate:** `velociraptor artifacts verify ./artifacts/*.yaml`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `velociraptor` | `velociraptor artifacts verify <paths> [-v] [--nowall]` | Static analysis of artifact YAML and VQL; non-zero exit on issues | Cross-platform |
| `velociraptor` | `velociraptor artifacts collect <name> --args K=V --format json` | Run one artifact locally against the current host | Cross-platform |
| `velociraptor` | `velociraptor artifacts list` | Enumerate artifacts known to the binary | Cross-platform |
| `velociraptor` | `velociraptor query "SELECT ..." --format json` | Run ad-hoc VQL for exploration | Cross-platform |
| `velociraptor` | `velociraptor config generate > server.config.yaml` | Generate a server configuration for a new deployment | Cross-platform |
| VQL plugin | `glob(globs=..., accessor="auto")` | Path discovery separated from parsing | VQL |
| VQL plugin | `parse_evtx(filename=..., accessor=...)` | Decode Windows event logs; the expensive step, always filter after | VQL |
| VQL plugin | `parse_pe(file=...)`, `parse_prefetch`, `parse_mft`, `parse_ntfs` | Binary and filesystem artifacts | VQL |
| VQL plugin | `yara(rules=..., files=...)`, `yara_lint` | Signature scanning inside a collection | VQL |
| VQL plugin | `read_reg_key(path=...)`, `registry_key(...)` | Registry values | VQL |
| VQL function | `expand(path=...)`, `timestamp(epoch=...)`, `get(field=..., item=...)` | Environment expansion, time conversion, safe field access | VQL |

## Minimal Script

```powershell
velociraptor.exe artifacts verify .\artifacts\*.yaml
$verify = $LASTEXITCODE
if ($verify -ne 0) { Write-Output "verify failed: $verify"; exit 2 }

velociraptor.exe artifacts collect Custom.Windows.EventLogs.PowerShellScriptBlock --format json |
    Set-Content .\build\ps4104.json
$collect = $LASTEXITCODE
$rows = (Get-Content .\build\ps4104.json | Measure-Object -Line).Lines
Write-Output "collect=$collect rows=$rows"
if ($collect -ne 0) { exit 1 }
```

Exit-code contract: `0` artifact verified and collection completed within resource limits, `1` verify issue or truncated/failed collection, `2` missing artifact file or unreadable path.
