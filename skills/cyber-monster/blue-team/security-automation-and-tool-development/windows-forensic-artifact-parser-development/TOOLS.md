# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-forensic-artifact-parser-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `regipy` (>= 6.5, `RegistryHive`, `get_key`, `iter_values`, `recurse_subkeys`, plugin layer) for hives, `pyscca`/`libscca` for Prefetch, `LnkParse3` for shortcuts, `dissect.target` or `dfir_ntfs` for `$MFT`/`$UsnJrnl`
- **Validation Gate:** `python -m py_compile artifact_parse.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `regipy` | `RegistryHive(path)` then `get_key(...)` / `recurse_subkeys(as_json=True)` | Walk hive keys and values | Python >= 3.9 |
| `regipy` | plugin invocation (e.g. Amcache, Shimcache plugins) via `run_relevant_plugins` | Derived artefact extraction | Python |
| `regipy` CLI | `regipy-dump`, `regipy-apply-transaction-logs` (from `regipy[cli]`) | Dump a hive to JSON; apply logs | Cross-platform |
| `pyscca` | `pyscca.file()` → iterate prefetch entries | Prefetch parsing with libscca | Python |
| `LnkParse3` | `LnkParse3.lnk_file(fh).get_json()` | LNK target list, info block, tracker blocks | Python |
| `dissect.target` | `target-query -f mft <target>` / `-f usnjrnl` / `-f prefetch` | Framework-level artefact access over images and collections | Cross-platform |
| `dfir_ntfs` | `MFT`, `USNJRNL`, `LogFile` parsers | Direct `$MFT`, `$UsnJrnl:$J`, `$LogFile` parsing | Python 3 |
| Python `struct` | `struct.unpack_from("<Q", data, 120)` | Prefetch/`$MFT` fixed-offset reads with explicit widths | Python 3.11+ |
| Python `hashlib` | `sha256` streamed over 1 MB chunks | Chain-of-custody hashing without loading the file | Python 3.11+ |

## Minimal Script

```powershell
python .\artifact_parse.py .\evidence\SOFTWARE --sha256 <expected-hash> | Set-Content .\build\hive-rows.jsonl
$hive = $LASTEXITCODE
if ($hive -eq 2) { Write-Output "hash mismatch or unreadable input"; exit 2 }

python .\artifact_parse.py .\evidence\CMD.EXE-1234ABCD.pf | Set-Content .\build\pf-rows.jsonl
$pf = $LASTEXITCODE

$rows = (Get-Content .\build\hive-rows.jsonl,.\build\pf-rows.jsonl | Measure-Object -Line).Lines
Write-Output "hive=$hive prefetch=$pf total_rows=$rows"
```

Exit-code contract: `0` fully parsed, `1` a class returned nothing unexpectedly or a parse was partial, `2` hash mismatch or unreadable input.
