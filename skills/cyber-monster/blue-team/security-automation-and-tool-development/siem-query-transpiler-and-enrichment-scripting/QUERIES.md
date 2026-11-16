# Detection Queries and Telemetry Artifacts

> Sub-skill: [`siem-query-transpiler-and-enrichment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Query-execution and enrichment artifacts owned by this slug. Confirm field names per table and per platform version before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | DSL object query with the value under `term`/`match` | High | The value is data, so query structure cannot be rewritten |
| 2 | Allowlist rejection of a value containing a quote or newline | High | Text-platform injection is blocked before the query is built |
| 3 | `LogsQueryPartialResult` surfaced as partial | High | A truncated query is not reported as complete |
| 4 | Cache hit ratio above zero on a multi-alert incident | High | Enrichment scales with distinct entities, not alert count |
| 5 | `results.Message` entries separated from result dicts | High | Splunk diagnostics are visible rather than silently dropped |

## Detection Artifacts

```text
[siem-query-transpiler-and-enrichment-scripting:rule-spec] bind values as data; escape and allowlist only where the platform has no binding
[siem-query-transpiler-and-enrichment-scripting:filter-fp] partial results and empty results are different outcomes with different exit codes
[siem-query-transpiler-and-enrichment-scripting:correlate] entity key (host, IP, account) is the enrichment cache key
```

Elasticsearch structured query, where the value never enters query text (Windows PowerShell 5.1 invoking Python):

```python
import asyncio

from elasticsearch import AsyncElasticsearch

async def lookup(host: str, needle: str) -> list[dict]:
    client = AsyncElasticsearch(hosts=["https://es.example.internal:9200"], api_key=("id", "key"))
    try:
        resp = await client.search(
            index="logs-security-*",
            size=100,
            query={
                "bool": {
                    "filter": [
                        {"term": {"host.name": host}},
                        {"match_phrase": {"process.command_line": needle}},
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                    ]
                }
            },
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    finally:
        await client.close()

print(len(asyncio.run(lookup("web01", "powershell -enc"))))
```

Splunk one-shot query with JSON results and diagnostics kept separate:

```python
import splunklib.client as client
import splunklib.results as results

service = client.connect(host="splunk.example.internal", port=8089, token="<token>")
stream = service.jobs.oneshot(
    'search index=win SecurityEventId=4688 CommandLine="*powershell*" earliest=-24h | head 50',
    output_mode="json",
)
reader = results.JSONResultsReader(stream)
rows, messages = [], []
for item in reader:
    if isinstance(item, results.Message):
        messages.append(str(item))
    else:
        rows.append(item)
print(f"rows={len(rows)} messages={len(messages)} preview={reader.is_preview}")
```

Injection probe: a hostile value must be rejected, not merely quoted.

```python
SAFE_HOST = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
for probe in ["web01", "web01' | where 1==1 | //", "web01\n| take 1000"]:
    print(bool(SAFE_HOST.match(probe)), repr(probe))
```

Enrichment cache behaviour check, which must show one lookup for repeated entities:

```python
lookups = Counter()
for entity in ["10.0.0.5", "10.0.0.5", "10.0.0.9", "10.0.0.5"]:
    lookups[entity] += 1
distinct = len(lookups)
print("requests_if_cached=%d requests_if_not=%d" % (distinct, sum(lookups.values())))
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Record the query text (with values elided) alongside every result so a finding can be reproduced.
- Distinguish partial, empty, and failed outcomes in the caller's exit code.
- Check the enrichment database build date at startup and refuse to serve stale geo/ASN data silently.
