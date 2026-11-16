# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`static-pe-elf-apk-feature-extractor-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `pefile` (`PE(path, fast_load=True)`, `parse_data_directories`, `get_imphash`, section `get_data`), `lief` for cross-format parsing, `androguard` (`AnalyzeAPK`), `flare-capa` for capability labels — all static, all bounded
- **Validation Gate:** `python -m py_compile feature_extract.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pefile` | `pefile.PE(path, fast_load=True)` + `parse_data_directories([...])` | Parse PE headers lazily, then only the directories needed | Python |
| `pefile` | `pe.get_imphash()` | Ordered import-table hash for family clustering | Python |
| `pefile` | `section.get_data()` with a size check first | Section bytes for entropy computation | Python |
| `lief` | `lief.parse(path)` then `.imported_functions` / `.sections` | One API across PE/ELF/Mach-O | Python |
| `androguard` | `from androguard.misc import AnalyzeAPK; apk, dexes, dx = AnalyzeAPK(path)` | APK + DEX + cross-reference analysis | Python |
| `androguard` | `apk.get_permissions()`, `dx.get_classes()`, method `get_xref_from()` | LAMDA-style permission/API vectors | Python |
| `capa` (CLI) | `capa -r <rules_dir> -s <sig_dir> sample.exe` | Capability detection with explicit rule and signature paths | Cross-platform |
| `capa` (library) | `pip install flare-capa` (entry point `capa.main:main`) | Embeddable capability analysis; rules and sigs must be supplied | Python >= 3.10 |

## Minimal Script

```powershell
python -m py_compile .\feature_extract.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\feature_extract.py .\samples\sample.exe | Set-Content .\build\vec.json
$extract = $LASTEXITCODE
$skipped = (Select-String -Path .\build\vec.json -Pattern 'declared_size_over_cap' | Measure-Object).Count
Write-Output "extract=$extract skipped_structures=$skipped"
if ($extract -eq 2) { exit 2 }
exit $extract
```

Exit-code contract: `0` complete extraction, `1` partial (skipped structures recorded), `2` unparseable sample or unreadable path.
