# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osquery-extension-and-pack-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags or table names — run `osqueryi --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** osquery 5.20.x pack/config JSON (`packs.<pack>.queries.<name>` with `query`, `interval`, `snapshot`, `removed`, `platform`, `shard`, `denylist`) and `osquery-python` (`osquery.TablePlugin`, `osquery.TableColumn`, `osquery.register_plugin`, `osquery.start_extension`)
- **Validation Gate:** `osqueryi --json "SELECT * FROM <table> LIMIT 1"; python -m py_compile osquery_ext.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `osqueryi` | `osqueryi --json "SELECT ..."` | Run an ad-hoc query and get JSON | Cross-platform |
| `osqueryi` | `.schema <table>` | Confirm column names and types on this version | Cross-platform |
| `osqueryi` | `osqueryi --extension <path>` | Load an extension for a single shell session | Cross-platform |
| `osqueryd` | `--config_path <file> --verbose` | Run the daemon with a specific pack config | Cross-platform |
| `osqueryd` | `--ephemeral` | Run without persisting state, for pack validation | Cross-platform |
| `osqueryd` | `--enable_file_events=true`, `--disable_events=false` | Enable the file event publisher | Cross-platform |
| `osqueryi` | `SELECT * FROM osquery_flags` | Inspect effective flag values on a host | Cross-platform |
| `osqueryi` | `SELECT * FROM osquery_schedule` | Inspect scheduled query performance and denylist state | Cross-platform |
| `osquery-python` | `@osquery.register_plugin` + `class X(osquery.TablePlugin)` with `name`, `columns`, `generate` | Custom table | Python |
| `osquery-python` | `osquery.start_extension(name=..., version=...)` | Start the Thrift extension process | Python |

## Minimal Script

```powershell
osqueryi --json "SELECT name, value FROM osquery_flags WHERE name IN ('enable_file_events','disable_events');"
if ($LASTEXITCODE -ne 0) { Write-Output "osqueryi unavailable"; exit 2 }

$fim = osqueryi --json "SELECT * FROM file_events LIMIT 1;"
if ([string]::IsNullOrWhiteSpace($fim) -or $fim.Trim() -eq '[]') {
    Write-Output "file_events empty: check publisher flags and file_paths categories"
    exit 1
}

python -m py_compile .\osquery_ext.py
$compile = $LASTEXITCODE
Write-Output "compile=$compile"
exit $compile
```

Exit-code contract: `0` queries return the expected shape and the extension compiles, `1` a table expected to be populated is empty or a query is denylisted, `2` osquery missing or config rejected.
