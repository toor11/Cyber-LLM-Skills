# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`volatility3-plugin-and-memory-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags or plugin names — run `vol -h` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Volatility 3 (`volatility3.framework.interfaces.plugins.PluginInterface`, `volatility3.framework.requirements` with `ModuleRequirement`/`VersionRequirement`/`PluginRequirement`, `volatility3.framework.renderers.TreeGrid`, `volatility3.framework.symbols` ISF tables)
- **Never:** Volatility 2 profiles or `vol.py` plugin conventions
- **Validation Gate:** `python -m py_compile vol_plugin.py; vol -f image.raw windows.pslist`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `vol` | `vol -f <image> windows.info` | Confirm the image parses and report kernel/OS details | Cross-platform |
| `vol` | `vol -f <image> windows.pslist` | Walk the active process list | Cross-platform |
| `vol` | `vol -f <image> windows.psscan` | Pool-scan for `_EPROCESS`, including unlinked processes | Cross-platform |
| `vol` | `vol -f <image> windows.malfind` | Surface executable, unbacked or private VAD regions | Cross-platform |
| `vol` | `vol -f <image> windows.vadinfo --pid <pid>` | Enumerate VAD entries to corroborate `malfind` | Cross-platform |
| `vol` | `-r json` / `-r csv` / `--output-dir <dir>` | Structured output for downstream parsing | Cross-platform |
| `vol` | `vol -f <image> --symbols <path>` | Point at a specific ISF symbol directory | Cross-platform |
| Python | `interfaces.plugins.PluginInterface` subclass with `_version`, `_required_framework_version`, `get_requirements`, `run` | Plugin contract | Python |
| Python | `renderers.TreeGrid([(name, type), ...], generator)` | Typed tabular output | Python |
| Python | `requirements.ModuleRequirement(name="kernel", architectures=[...])` | Bind the plugin to a kernel symbol table | Python |

## Minimal Script

```powershell
$image = "C:\evidence\memory\workstation.raw"
vol -f $image windows.info
if ($LASTEXITCODE -ne 0) { Write-Output "image/symbols unusable"; exit 2 }

vol -f $image -r json windows.pslist | Set-Content .\build\pslist.json
$list = $LASTEXITCODE
vol -f $image -r json windows.psscan | Set-Content .\build\psscan.json
$scan = $LASTEXITCODE

$psRows = (Get-Content .\build\pslist.json | ConvertFrom-Json).Count
if ($psRows -eq 0) { Write-Output "pslist empty: symbol problem, not a clean image"; exit 1 }
Write-Output "pslist=$list rows=$psRows psscan=$scan"
```

Exit-code contract: `0` every plugin ran and produced plausible rows, `1` a plugin produced zero rows where rows are expected or the cross-view differential was skipped, `2` image unreadable or symbols unresolvable.
