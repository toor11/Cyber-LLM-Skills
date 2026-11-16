# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`siem-query-transpiler-and-enrichment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if an import or signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `azure-monitor-query` (`LogsQueryClient`, `LogsQueryStatus`, `query_workspace`/`query_resource` with an explicit `timespan`), `splunklib` (`client.connect`, `jobs.oneshot(output_mode="json")`, `results.JSONResultsReader`), `elasticsearch` 9.x (`AsyncElasticsearch.search(index=..., query=..., size=...)`)
- **Validation Gate:** `python -m py_compile siem_enrich.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `azure-monitor-query` | `LogsQueryClient(credential).query_workspace(workspace_id=..., query=..., timespan=(start, end))` | Run KQL over a workspace with an explicit window | Python |
| `azure-monitor-query` | `query_resource(resource_id, query, timespan=timedelta(days=1))` | Run KQL scoped to one Azure resource | Python |
| `azure-monitor-query` | `LogsQueryStatus.SUCCESS` / `LogsQueryPartialResult.partial_data` | Distinguish complete from truncated results | Python |
| `splunklib` | `client.connect(host=..., port=8089, token=...)` | Authenticate to the Splunk REST API | Python |
| `splunklib` | `service.jobs.oneshot(query, output_mode="json")` | Synchronous search returning a stream | Python |
| `splunklib` | `results.JSONResultsReader(stream)` | Iterate result dicts and `Message` diagnostics | Python |
| `elasticsearch` | `await AsyncElasticsearch(...).search(index=..., query={...}, size=...)` | DSL query with values as structured data | Python |
| `elasticsearch` | `client.search(index=..., q="...")` | Lucene query-string form; overrides a body `query` | Python |
| MaxMind | `geoip2.database.Reader("<mmdb>")` | Local IP-to-ASN/country lookup | Python |

## Minimal Script

```powershell
python -m py_compile .\siem_enrich.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\siem_enrich.py | Set-Content .\build\hunt.jsonl
$hunt = $LASTEXITCODE
Write-Output "hunt exit=$hunt"
if ($hunt -eq 2) { Write-Output "auth or transport failure - not an empty result" }
exit $hunt
```

Exit-code contract: `0` query complete within its window, `1` partial result or a value rejected by the allowlist, `2` authentication or connectivity failure.
