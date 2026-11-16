# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`siem-query-and-log-analysis`](SKILL.md) | Family: **Detection and Monitoring**

Backend-neutral entry points for running, exporting and reconciling a query. Platform-specific flag sets live in the three variant leaves; this file covers what they have in common and how to move data out of each without losing fidelity. Never invent undocumented flags — check `--help` or the API reference for the installed version.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Splunk REST export | `curl -k -u <user>:<pass> https://<sh>:8089/services/search/jobs/export -d search="<SPL>" -d output_mode=json` | Stream results out of Splunk without the web UI | Any host with HTTPS to 8089 |
| Elasticsearch `_search` | `curl -s -u "$AUTH" "$ES/_search" -H 'Content-Type: application/json' -d @query.json` | Run DSL and inspect `hits.total` and `_shards.failed` for completeness | Any host with HTTPS to Elasticsearch |
| Elasticsearch `_eql/search` | `curl -s -u "$AUTH" "$ES/$INDEX/_eql/search?allow_partial_search_results=false" -d @seq.json` | Run a sequence and fail loudly on shard problems instead of returning partials | Same |
| Microsoft Graph / Log Analytics | `POST https://api.loganalytics.io/v1/workspaces/<id>/query` with `{"query": "..."}` | Run KQL outside the portal, reading the response's `tables` and any partial-error flag | Any host with a token |
| `sigma` conversion | `sigma convert -t splunk -p <pipeline> rules/` and the equivalent backends | Reuse a backend-neutral rule rather than hand-transcribing a query | Cross-platform |
| `jq` | `jq -c '.tables[0].rows[]'` and `.hits.total.value` | Normalise three different response envelopes into one row stream | Linux, macOS, Windows |
| `sqlite3` | `sqlite3 q.db ".import rows.csv r"` then SQL for the differential | Reproducible join and delta arithmetic outside any one platform | Linux, macOS, Windows |

## Minimal Script Shape

The shape below is the minimum defensible cross-backend pull: it refuses to compare two windows unless both report completeness, then computes the per-key delta.

```bash
#!/usr/bin/env bash
# siem-diff.sh — pull the same aggregation for two windows, refuse partial results.
set -euo pipefail

ES="${ES:?elasticsearch base url}"
IDX="${IDX:-wineventlog-*}"
AUTH="${ES_AUTH:?user:pass}"
BODY='{"size":0,"query":{"bool":{"filter":[{"term":{"event.code":"4624"}},
  {"range":{"@timestamp":{"gte":"NOW_MINUS","lte":"NOW"}}}]}},
  "aggs":{"k":{"terms":{"field":"user.name","size":200},
  "aggs":{"h":{"terms":{"field":"host.name","size":50}}}}}}'

pull() { # pull <earliest> <latest> <outfile>
  local body="${BODY/NOW_MINUS/$1}"
  curl -sS -u "$AUTH" "$ES/$IDX/_search?allow_partial_search_results=false" \
    -H 'Content-Type: application/json' -d "${body/NOW/NOW}" > "$3"
  # Completeness gate: any failed shard makes the window unusable.
  jq -e '._shards.failed == 0' "$3" >/dev/null \
    || { echo "GAP: shard failures in $1..$2 -> INCONCLUSIVE"; exit 2; }
}

pull "now-14d/d" "now-7d/d" /tmp/base.json
pull "now-24h/h" "now/h"     /tmp/probe.json

jq -s '.[0].aggregations.k.buckets as $b | .[1].aggregations.k.buckets as $p
| [ $p[] | .key as $k | .doc_count as $c
    | { key: $k, probe: $c,
        baseline: ($b[] | select(.key == $k) | .doc_count // 0) } ]
| map(. + { ratio: (if .baseline == 0 then null else (.probe / .baseline) end) })
| sort_by(-.probe) | .[0:20]' /tmp/base.json /tmp/probe.json
```

## Notes That Prevent Wrong Runs

- `allow_partial_search_results=false` is the only way to make a shard problem fail loudly; with the default the response carries `_shards.failed` and partial data that reads as a complete answer.
- Log Analytics and Graph responses report partial errors separately from results; a non-empty `tables` array with an error block is a partial answer.
- Splunk's export endpoint streams and does not paginate; for large sets, dispatch a job and poll its results with `offset`/`count` so truncation is explicit.
- Never compare two windows pulled with different `size` or `terms` limits; the second window's tail is cut at a different point and the delta becomes an artefact of the limit.
