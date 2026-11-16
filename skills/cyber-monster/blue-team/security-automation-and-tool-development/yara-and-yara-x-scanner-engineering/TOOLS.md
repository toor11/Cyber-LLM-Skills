# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`yara-and-yara-x-scanner-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `yr --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `yara-x` >= 1.23 Python bindings (`yara_x.Compiler`, `yara_x.Scanner`, `scan`, `scan_file`, `set_timeout`, `max_matches_per_pattern`) and the `yr` CLI (`yr scan`, `yr compile`)
- **Retained for one case only:** classic `yara-python` for live process-memory scanning, which the YARA-X Python bindings do not expose
- **Validation Gate:** `python -m py_compile yara_scan_gate.py; yr compile rules/`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `yr` | `yr scan [OPTIONS] <RULES_PATH>... <TARGET_PATH>` | Scan a file or directory with source rules or a compiled ruleset | Cross-platform |
| `yr` | `yr compile rules/` | Compile source rules; non-zero exit on any rule error | Cross-platform |
| `yr` | `yr scan -C rules.yarc target/` | Scan with a precompiled `.yarc` artifact (`-C`/`--compiled-rules` accepts one rules path only) | Cross-platform |
| `yr` | `yr scan -r rules/ samples/` | Recurse into a directory (`-r`/`--recursive` with optional depth) | Cross-platform |
| `yr` | `yr scan --output-format ndjson rules/ samples/` | One JSON object per file: `text`, `ndjson`, or `json` | Cross-platform |
| `yr` | `yr scan --timeout 30 rules/ samples/` | Abort a scan after N seconds | Cross-platform |
| `yr` | `yr scan --threads 4 rules/ samples/` | Scanning thread count | Cross-platform |
| `yr` | `yr scan --max-matches-per-pattern 100 rules/ samples/` | Cap matches per pattern to bound output size | Cross-platform |
| `yr` | `yr scan --profiling rules/ corpus/` | Per-rule timing to find pathological atoms | Cross-platform |
| `yr` | `yr scan --scan-list rules/ targets.txt` | Target list from a file, one path per line | Cross-platform |
| `yr` | `yr scan --module-data MODULE=FILE rules/ samples/` | Populate a module's external data | Cross-platform |
| `yara_x` (Python) | `yara_x.compile(source)` / `yara_x.Compiler()` | Compile a single rule set or multiple namespaces | Python >= 3.9 |
| `yara_x` (Python) | `Scanner(rules).scan(bytes)` / `.scan_file(path)` | Scan a blob or a path; raises `TimeoutError` on timeout | Python >= 3.9 |

## Minimal Script

```powershell
python -m pip install --upgrade yara-x
yr --version
yr compile .\rules\ | Out-Host
$compileExit = $LASTEXITCODE
if ($compileExit -ne 0) { Write-Error "yr compile failed: $compileExit"; exit 2 }
yr scan --timeout 30 --max-matches-per-pattern 100 --output-format ndjson .\rules\ .\fixtures\positive\
python -m py_compile .\yara_scan_gate.py
```

Exit-code contract: `0` positive matched and clean-ware did not, `1` differential broken (miss or false positive), `2` compile error, missing rule tree, or missing fixture.
