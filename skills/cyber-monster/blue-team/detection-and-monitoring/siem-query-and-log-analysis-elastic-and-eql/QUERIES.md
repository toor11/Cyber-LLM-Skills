# Detection Queries and Telemetry Artifacts

> Sub-skill: [`siem-query-and-log-analysis-elastic-and-eql`](SKILL.md) | Family: **Detection and Monitoring**

EQL, Elasticsearch DSL and piped-query artifacts owned by `siem-query-and-log-analysis-elastic-and-eql`. Field names are ECS as shipped in the Elastic Security mappings; confirm against `_field_caps` for your index pattern before deploying, because removed ECS fields return empty rather than erroring. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Scope, mapping and completeness gate

Expected hit: the index pattern carries the decisive fields at the expected type, and the response reports zero failed shards. Either failing makes the later classes uninterpretable.

```text
GET logs-*/_field_caps?fields=event.category,event.outcome,user.name,source.ip,host.name
```

```json
GET logs-*/_search?allow_partial_search_results=false
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-1d" } } },
  "aggs": { "by_dataset": { "terms": { "field": "event.dataset", "size": 50 } } }
}
```

False-positive note: a data stream that stopped writing yesterday and a data stream that was never created look identical in `_field_caps`; check `_data_stream` status and the last `@timestamp` before calling it a gap.

## Class 2 — Aggregation with an honest bucket count

Expected hit: `sum_other_doc_count` at zero, or a size large enough that the remainder is irrelevant. A nonzero remainder means the rare value you are hunting may sit outside the returned buckets.

```json
GET logs-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term": { "event.code": "4624" } },
    { "range": { "@timestamp": { "gte": "now-24h" } } }
  ]}},
  "aggs": {
    "by_user": {
      "terms": { "field": "user.name", "size": 500 },
      "aggs": { "by_host": { "terms": { "field": "host.name", "size": 200 } } }
    }
  }
}
```

False-positive note: a very high `sum_other_doc_count` on `user.name` is normal in a large estate; the fix is a second query scoped to the tail, not a bigger `size` that times out.

## Class 3 — Sequence with explicit join keys

Expected hit: ordered matches where the anchor and the consequence share a stable entity, with `is_partial` false. Joining on the user alone pairs unrelated hosts.

```eql
sequence by user.name, source.ip with maxspan=10m
  [ authentication where event.outcome == "failure" and source.ip != null ] with runs=5
  [ authentication where event.outcome == "success" and source.ip != null ]
```

```json
POST /logs-*/_eql/search?allow_partial_search_results=false
{
  "query": "sequence by host.name with maxspan=5m [ process where process.name == \"certutil.exe\" ] [ file where event.action == \"creation\" and file.extension in (\"exe\", \"dll\") ]",
  "size": 100,
  "timestamp_field": "@timestamp"
}
```

False-positive note: `is_partial: true` in the response means a shard failed and the surviving matches are incomplete; discard the result rather than reporting a smaller number.

## Class 4 — Process lineage and rare-parent hunting

Expected hit: parent-child pairs that appear rarely across the fleet for that parent, which is where living-off-the-land execution shows up. Prevalence, not the pair itself, is the discriminator.

```eql
process where event.type == "start"
  and process.parent.name in ("winword.exe", "excel.exe", "outlook.exe")
  and not process.name in ("splwow64.exe", "rundll32.exe")
```

```text
FROM logs-endpoint.events.process-*
| WHERE event.type == "start"
| STATS hosts = COUNT_DISTINCT(host.name), runs = COUNT(*) BY process.parent.name, process.name
| WHERE hosts <= 2 AND runs >= 4
| EVAL scarcity = 1.0 / hosts
| SORT scarcity DESC, runs DESC
```

False-positive note: a newly deployed line-of-business add-in produces a rare parent-child pair on a handful of hosts; require the command line or the child's location to be inconsistent before escalating.

## Class 5 — Enrichment against a lookup index

Expected hit: events whose indicator resolves to a known-bad entry or to a documented asset owner. A lookup join adds context at query time without an ingest policy.

```text
FROM logs-network_traffic.*
| WHERE event.category == "network"
| LOOKUP JOIN threat_intel_lookup ON destination.ip
| WHERE threat.label IS NOT NULL
| STATS hits = COUNT(*) BY source.ip, destination.ip, threat.label
| SORT hits DESC
```

False-positive note: lookup joins are a technical preview and return one row per match; a feed with duplicate indicators multiplies the event count. Deduplicate the lookup index before reading volume from this query.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the ECS version, the index pattern and `allow_partial_search_results` beside every saved query; without them a zero cannot be distinguished from a partial result.
