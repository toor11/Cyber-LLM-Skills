# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`security-arsenal-and-tool-index`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a versioned YAML index with `technique`, `tool`, `version`, `invocation`, `format`, `blind_spot`, `alternative`.
- **Validation Gate:** one entry's invocation run against a lab target with its output format confirmed.
- Pin versions in the index; an unpinned tool turns a reproducible method into a recollection.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(len(yaml.safe_load(open('index.yaml'))['entries']))"` | Count and validate index entries | Cross-platform |
| `nmap` | `nmap --version` | Confirm the scanner version the entry was validated against | Cross-platform |
| `jq` | `jq -r '.entries[].tool' index.json` | List tools when the index is JSON | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess
import yaml

index = yaml.safe_load(open("index.yaml", encoding="utf-8"))
for entry in index["entries"]:
    try:
        out = subprocess.run([entry["tool"], "--version"], capture_output=True, text=True, timeout=10)
        print(entry["tool"], entry["version"], out.stdout.splitlines()[:1])
    except (OSError, subprocess.SubprocessError) as exc:
        print(entry["tool"], "unavailable", type(exc).__name__)
```
