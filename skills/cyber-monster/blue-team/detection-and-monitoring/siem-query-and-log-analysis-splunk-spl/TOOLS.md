# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`siem-query-and-log-analysis-splunk-spl`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for running and exporting SPL outside the web UI. Never invent undocumented flags — check `splunk help search` on the installed version, because flag sets differ between the `splunk` CLI and the `splunkd` REST handler.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `splunk` CLI (search) | `splunk search "<SPL>" -auth <user>:<pass> -earliest_time -24h -latest_time now -maxout 0 -preview false` | Run one SPL search, block until done, print results | Search head |
| `splunk` CLI (dispatch) | `splunk search "<SPL>" -auth <user>:<pass> -earliest_time -7d -maxout 100000 > out.csv` | Export bounded results for offline differential analysis | Search head |
| REST export endpoint | `curl -k -u <user>:<pass> https://<sh>:8089/services/search/jobs/export -d search="<SPL>" -d earliest_time=-24h -d latest_time=now -d output_mode=json` | Streaming JSON export; the only stable machine-readable path | Any host with HTTPS to 8089 |
| REST job inspection | `curl -k -u <user>:<pass> https://<sh>:8089/services/search/jobs/<sid>?output_mode=json` | Read `dispatchState`, `doneProgress`, `messages` (truncation, partial results) | Any host with HTTPS to 8089 |
| `rest` search command | `rest /services/search/jobs splunk_server=local` then `table title, dispatchState, doneProgress` | Inspect job health from inside a search | Search head |
| `tstats` + `metadata` commands | `tstats summariesonly=t count FROM datamodel=Endpoint.Processes BY Processes.dest` | Summary counts and coverage enumeration without raw scans | Search head |
| `sigma-cli` | `sigma list pipelines && sigma convert -t splunk -p <pipeline> rules/` | Convert Sigma rules into SPL for this deployment | Cross-platform |
| `btool` | `btool props list` / `btool transforms list` | Confirm which `sourcetype` actually extracts a field | Search head / indexer |

## Minimal Script Shape

The shape below is the minimum that produces a defensible answer: it enumerates the source, runs the identical aggregation over a baseline window and a probe window, and refuses to report a raw count without its delta.

```bash
#!/usr/bin/env bash
# spl-differential.sh — baseline-vs-probe SPL differential with an explicit gap check.
set -euo pipefail

SH="${SPLUNK_HOST:?set SPLUNK_HOST}"
AUTH="${SPLUNK_AUTH:?set SPLUNK_AUTH as user:pass}"
IDX="${IDX:-wineventlog}"
ST="${ST:-WinEventLog:Security}"
AGG='EventCode=4624 | eval k=coalesce(src,ComputerName)."|".coalesce(TargetUserName,"-") | stats count AS c by k'

run() { # run <earliest> <latest> <query>
  curl -sS -k -u "$AUTH" "https://${SH}:8089/services/search/jobs/export" \
    --data-urlencode "search=index=${IDX} sourcetype=\"${ST}\" $3" \
    --data-urlencode "earliest_time=$1" --data-urlencode "latest_time=$2" \
    --data-urlencode "output_mode=json"
}

# 0. Coverage gate: refuse to interpret an empty source.
run -7d now '| metadata type=sourcetypes | table sourcetype,totalCount,lastTime' \
  | grep -q "\"${ST}\"" || { echo "GAP: ${ST} not onboarded -> INCONCLUSIVE"; exit 2; }

# 1. Identical aggregation, two windows.
run -14d@d @d "$AGG"   > /tmp/baseline.json
run -24h@h   @h "$AGG" > /tmp/probe.json

# 2. Report only the delta, per key.
python3 - <<'PY'
import json
def load(p):
    rows = [json.loads(l) for l in open(p) if l.strip()]
    return {r["result"]["k"]: float(r["result"]["c"]) for r in rows if "result" in r}
base, probe = load("/tmp/baseline.json"), load("/tmp/probe.json")
for k, c in sorted(probe.items(), key=lambda x: -x[1]):
    b = base.get(k, 0.0)
    if c > 5 and (b == 0 or c / b >= 3):
        print(f"{k:60s} baseline={b:8.0f} probe={c:8.0f} ratio={(c/b if b else float('inf')):.1f}")
PY
```

## Notes That Prevent Wrong Runs

- `-maxout 0` disables the row cap. Any nonzero cap turns a truncated result into a silent partial answer; if you must cap, record the cap beside the finding.
- The export endpoint streams; it does not paginate. For very large results, dispatch a normal job and poll `/services/search/jobs/<sid>/results` with `offset`/`count` instead.
- `-preview false` waits for final results. Preview results are partial and must never be compared across windows, because the two windows will be at different completion points.
- `| metadata` answers "what exists"; it does not answer "what happened". Use it as a gate, never as evidence.
