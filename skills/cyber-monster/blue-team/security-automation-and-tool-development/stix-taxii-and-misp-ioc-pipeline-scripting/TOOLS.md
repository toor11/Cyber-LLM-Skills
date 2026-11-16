# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`stix-taxii-and-misp-ioc-pipeline-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed client version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `stix2` >= 3.0 (STIX 2.1 `Indicator`, `pattern_type="stix"`, `valid_from`/`valid_until`, `parse`/`serialize`), `taxii2client.v21` (`Server`, `ApiRoot`, `Collection`, `as_pages`), `PyMISP` >= 2.5 (`PyMISP`, `MISPEvent`, `MISPAttribute`, `add_event`/`add_attribute`)
- **Validation Gate:** `python -m py_compile ioc_pipeline.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `stix2` | `Indicator(name=..., pattern_type="stix", pattern=..., valid_from=..., valid_until=...)` | Build a compliant indicator with a validity window | Python >= 3.10 |
| `stix2` | `stix2.parse(json_text)` / `obj.serialize()` | Parse a bundle and re-serialize | Python |
| `taxii2client` | `from taxii2client.v21 import Server, Collection, as_pages` | TAXII 2.1 discovery and paged reads | Python |
| `taxii2client` | `collection.get_objects()` / `collection.add_objects(bundle)` | Read and publish objects | Python |
| `taxii2client` | `as_pages(collection.get_objects, per_request=50)` | Iterate all pages of a large collection | Python |
| `PyMISP` | `PyMISP(url, key, ssl=True, timeout=30)` | Authenticate with TLS verification on | Python |
| `PyMISP` | `MISPEvent()` with `add_attribute(type, value)` then `misp.add_event(event, pythonify=True)` | Create a restricted event with attributes | Python |
| `PyMISP` | `misp.search(controller="attributes", type_attribute=..., value=...)` | Look up an existing attribute before adding | Python |
| Python `ipaddress` | `ip_address(x).is_private` / `is_loopback` / `is_link_local` | Self-harm filters for IP indicators | Python 3.11+ |

## Minimal Script

```powershell
python -m py_compile .\ioc_pipeline.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\ioc_pipeline.py .\feeds\bundle.json | Set-Content .\build\ioc-decisions.jsonl
$run = $LASTEXITCODE
$enforce = (Select-String -Path .\build\ioc-decisions.jsonl -Pattern '"outcome": "enforce"' | Measure-Object).Count
$dropped = (Select-String -Path .\build\ioc-decisions.jsonl -Pattern '"outcome": "drop"' | Measure-Object).Count
Write-Output "enforce=$enforce dropped=$dropped exit=$run"
exit $run
```

Exit-code contract: `0` all objects classified, `1` an object requires review (unsupported pattern type), `2` transport, authentication, or parse failure.
