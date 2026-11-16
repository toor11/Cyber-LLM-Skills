# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`siem-query-and-log-analysis-kql-and-sentinel`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for running KQL outside the portal and for inspecting ingestion tier. Never invent endpoint paths or flags — check `az monitor log-analytics query --help` on the installed CLI, because parameter names changed across CLI releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Log Analytics Query API | `POST https://api.loganalytics.io/v1/workspaces/<workspace-id>/query` with a `query` and `timespan` field | Run KQL outside the portal and read `tables` plus any partial-error block | Any host with a token |
| `az monitor log-analytics query` | `az monitor log-analytics query -w <workspace-id> --analytics-query "<KQL>" --timespan PT24H` | Same query from a shell with Azure CLI auth, returning JSON | Cross-platform |
| `az monitor log-analytics workspace table show` | `az monitor log-analytics workspace table show --workspace-name <ws> -g <rg> -n DeviceProcessEvents` | Read the table's retention and plan, confirming the tier and window ceiling | Cross-platform |
| `az monitor log-analytics workspace table list` | `az monitor log-analytics workspace table list --workspace-name <ws> -g <rg> -o table` | Enumerate tables that exist in the workspace at all | Cross-platform |
| Sentinel data lake KQL | Advanced Hunting in the Defender portal under Investigation and Response, with the lake table selected | Query lake-only data interactively where the Logs blade cannot see it | Browser |
| `_GetWatchlist` | `_GetWatchlist('name')` inside a query | Join against a managed list without an ingest pipeline | Portal and API |
| `jq` | Map `.tables[]` to its `.columns` names and then to `.rows` as CSV | Flatten the Query API envelope into rows for offline comparison | Linux, macOS, Windows |

## Minimal Script Shape

The shape below is the minimum defensible KQL pull: it confirms the table exists with data in the window, then pulls two windows with an identical summarize shape and computes the per-key delta.

```bash
#!/usr/bin/env bash
# kql-diff.sh — table gate, then an identical aggregation over two windows.
set -euo pipefail

WS="${WS:?log analytics workspace id}"
TOKEN="${TOKEN:?bearer token for api.loganalytics.io}"
TABLE="${TABLE:-SigninLogs}"
KEY="${KEY:-UserPrincipalName}"

q() { # q <timespan> <kql> <out>
  curl -sS -X POST "https://api.loganalytics.io/v1/workspaces/${WS}/query" \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg q "$2" --arg t "$1" '{query:$q, timespan:$t}')" > "$3"
}

# 0. Gate: the table must exist and carry data in the last day.
q "PT24H" "${TABLE} | summarize n = count()" /tmp/kq_gate.json
jq -e '.tables[0].rows[0][0] > 0' /tmp/kq_gate.json >/dev/null \
  || { echo "GAP: ${TABLE} empty in window -> INCONCLUSIVE (Telemetry Gap)"; exit 2; }

AGG="${TABLE} | summarize c = count() by ${KEY}, bin(TimeGenerated, 1d)"
q "P14D" "$AGG" /tmp/kq_base.json
q "PT24H" "$AGG" /tmp/kq_probe.json

jq -r --slurpfile b /tmp/kq_base.json '
  [ .tables[0].rows[] | { key: .[0], probe: .[2] } ] as $p
  | [ $b[0].tables[0].rows[] | { key: .[0], base: .[2] } ] as $base
  | $p[] | .key as $k
  | . + { baseline: ([ $base[] | select(.key == $k) | .base ] | add // 0) }
  | select(.probe > 5) | [ .key, .baseline, .probe ] | @csv
' /tmp/kq_probe.json
```

## Notes That Prevent Wrong Runs

- The Query API's `timespan` and an in-query `where TimeGenerated` are additive, not alternatives; a wide `timespan` with a narrow `where` is fine, the reverse silently widens the scan.
- `az monitor log-analytics query` returns the same envelope as the API; parse `tables[].rows` rather than assuming a flat array.
- A lake-only table has no analytics-tier retention to inspect. If `table show` reports no plan for it, check the Defender portal rather than assuming the workspace can serve the query.
- Interactive lake queries are bounded by row, size and timeout limits; a recurring detection over lake data belongs in a scheduled job or summary rule, not in an analytics rule that cannot read the tier at all.
