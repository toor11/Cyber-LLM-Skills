# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`siem-query-and-log-analysis-elastic-and-eql`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for the three Elasticsearch query surfaces. Never invent parameters — check the running cluster's API docs, because default values (notably `allow_partial_search_results`) changed in 9.0.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `_search` (DSL) | `curl -s -u "$AUTH" "$ES/$IDX/_search?allow_partial_search_results=false" -H 'Content-Type: application/json' -d @q.json` | Aggregations and filtering with an explicit completeness guarantee | Any host with HTTPS to Elasticsearch |
| `_eql/search` | `curl -s -u "$AUTH" "$ES/$IDX/_eql/search?allow_partial_search_results=false" -d @seq.json` | Ordered correlation; the flag makes shard failure fatal | Any host with HTTPS to Elasticsearch |
| `_field_caps` | `curl -s -u "$AUTH" "$ES/$IDX/_field_caps?fields=event.category,user.name"` | Confirm a field exists and its type before writing a filter on it | Any host with HTTPS to Elasticsearch |
| `_data_stream` | `curl -s -u "$AUTH" "$ES/_data_stream/logs-*"` | Show which backing indices exist and whether the stream is healthy | Any host with HTTPS to Elasticsearch |
| `_cat/indices` | `curl -s -u "$AUTH" "$ES/_cat/indices/logs-*?v&h=index,docs.count,store.size,status"` | Fast inventory of what actually holds data in the window | Any host with HTTPS to Elasticsearch |
| `_eql/search` result fetch | `curl -s -u "$AUTH" "$ES/$IDX/_search" -d '{"query":{"ids":{"values":["<doc id>"]}},"_source":["process","file","host"]}'` | Retrieve full events behind a sequence join key | Any host with HTTPS to Elasticsearch |
| Kibana Dev Tools | `POST logs-*/_eql/search` in the console, with the request body as JSON not a string | Interactive iteration without shell quoting problems | Browser |

## Minimal Script Shape

The shape below is the minimum defensible Elastic pull: it gates on field availability, refuses partial results, and computes a per-key delta from two identical aggregation bodies.

```bash
#!/usr/bin/env bash
# elastic-diff.sh — field gate, completeness gate, then per-key delta.
set -euo pipefail

ES="${ES:?elasticsearch base url}"
IDX="${IDX:-logs-*}"
AUTH="${ES_AUTH:?user:pass}"
FIELD="${FIELD:-user.name}"

# 0. Mapping gate: the decisive field must exist for this pattern.
curl -s -u "$AUTH" "$ES/$IDX/_field_caps?fields=$FIELD,event.category" \
  | jq -e --arg f "$FIELD" '.fields[$f] != null' >/dev/null \
  || { echo "GAP: $FIELD absent from $IDX -> INCONCLUSIVE (Mapping Gap)"; exit 2; }

agg() { # agg <gte> <lte> <out>
  curl -s -u "$AUTH" "$ES/$IDX/_search?allow_partial_search_results=false" \
    -H 'Content-Type: application/json' -d "{
      \"size\": 0,
      \"query\": {\"bool\": {\"filter\": [
        {\"range\": {\"@timestamp\": {\"gte\": \"$1\", \"lte\": \"$2\"}}}
      ]}},
      \"aggs\": {\"k\": {\"terms\": {\"field\": \"$FIELD\", \"size\": 500}}}
    }" > "$3"
  jq -e '._shards.failed == 0' "$3" >/dev/null \
    || { echo "GAP: shard failures in $1..$2 -> INCONCLUSIVE"; exit 3; }
  jq -e '.aggregations.k.sum_other_doc_count == 0' "$3" >/dev/null \
    || echo "WARN: terms tail truncated; rare values may be missing"
}

agg "now-14d/d" "now-7d/d" /tmp/ebase.json
agg "now-24h/h" "now/h"     /tmp/eprobe.json

jq -s '.[0].aggregations.k.buckets as $b | .[1].aggregations.k.buckets as $p
| [ $p[] | .key as $k | { key: $k, probe: .doc_count,
    baseline: ($b[] | select(.key == $k) | .doc_count // 0) } ]
| map(select(.probe > 5)) | sort_by(-.probe) | .[0:20]' \
  /tmp/ebase.json /tmp/eprobe.json
```

## Notes That Prevent Wrong Runs

- `allow_partial_search_results` defaults to `true` from Elasticsearch 9.0. Set it false on every security query; `is_partial` and `shard_failures` in the response are the only other signal.
- `_field_caps` reports types per index; a field mapped as `text` and queried as a `term` returns nothing, so check the type before assuming the data is missing.
- A `terms` aggregation is per-shard then merged; `sum_other_doc_count` reports the merged remainder, which is the number that tells you whether the tail survived.
- Piped-query lookup joins are a technical preview. Treat their results as enrichment, not as the authoritative population count.
