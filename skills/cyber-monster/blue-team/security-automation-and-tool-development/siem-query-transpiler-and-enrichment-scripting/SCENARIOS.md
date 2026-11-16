# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`siem-query-transpiler-and-enrichment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative query/enrichment failures, each with the artifact that proves the diagnosis.

## Case 1: An alert field rewrote the query

- **Surface & Preconditions:** a hunting script builds `where Computer == '{host}'` from an alert's hostname field.
- **Root cause & impact:** a hostname containing a quote and a pipe adds a clause, so the query silently searches a broader or different set than intended. In a hunting tool this produces plausible results attributed to the wrong host.
- **Verification & fix:** allowlist the hostname pattern, escape the literal, and add a probe test with `web01' | where 1==1 | //` that must be rejected rather than quoted into a valid clause.

## Case 2: Truncated hunt reported as complete

- **Surface & Preconditions:** an Azure query spans 30 days on a high-volume workspace.
- **Root cause & impact:** the service returns a partial result; the wrapper reads `response.tables`, which does not exist on the partial object, or treats an empty table as "no matches". The hunt concludes the host is clean.
- **Verification & fix:** branch on `LogsQueryStatus` and surface `partial_error` plus the partial rows with a distinct exit code.

## Case 3: Enrichment storm during a real incident

- **Surface & Preconditions:** an enrichment function resolves each alert's source IP by calling an external API.
- **Root cause & impact:** an incident with several hundred alerts from a handful of IPs produces hundreds of identical lookups; the API rate-limits, lookups fail, and alerts flow onward unenriched — exactly when enrichment matters most.
- **Verification & fix:** key a bounded-TTL cache on the entity, pre-load the local MaxMind database, and record the cache hit ratio in the run summary.

## Case 4: Splunk diagnostics mistaken for results

- **Surface & Preconditions:** a search returns a warning message and no rows.
- **Root cause & impact:** `results.Message` items are yielded alongside result dicts; code that assumes every item is a dict either crashes or counts the message as a row, so a broken search looks like it returned data.
- **Verification & fix:** filter on `isinstance(item, dict)` versus `results.Message`, log messages separately, and fail the run when messages indicate a search error.
