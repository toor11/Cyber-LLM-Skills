# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`alert-tuning-and-false-positive-reduction`](SKILL.md) | Family: **Detection and Monitoring**

The tools below produce the three numbers a tune is judged on: suppressed volume, surviving volume, and re-fire result. Never invent undocumented flags — check `--help` on the installed version, because pySigma and sigma-cli flag sets move between minor releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma-cli` | `sigma check rules/` then `sigma convert -t splunk -p splunk_windows rules/proc_access_lsass.yml` | Lint a rule and compile it to the backend you deploy, so the exclusion can be read in the syntax that actually runs | Cross-platform |
| `sigma-cli` backend list | `sigma list targets` and `sigma list pipelines` | Confirm the pipeline names on the installed version before referencing one in CI | Cross-platform |
| `pySigma` library API | `from sigma.collection import SigmaCollection` then `SigmaCollection.from_yaml(text)` | Load rules programmatically to assert conditions and count selectors in regression tests | Python 3.10+ |
| Splunk `splunk` CLI | `splunk search "<SPL>" -auth <user>:<pass> -earliest_time -30d -latest_time now -maxout 0 -preview false` | Run the disposition join and the shadow differential against the alert index | Search head |
| Elastic `_search` with EQL | `POST /detections-*/_eql/search?filter_path=hits.total` with `{"query":"any where rule_id == \"...\""}` | Count rule fires per day on an Elastic detection index when the backend is Elastic | Elasticsearch 9.x |
| `yr` (YARA-X) | `yr scan --output-format ndjson -C compiled.yarc sample.bin` | Regression-scan a positive fixture when the tuned rule has a file-match component | Cross-platform |
| `git` | `git log --follow -p -- detections/cred_dump_lsass_access.yml` | Recover the rule's change history to prove which version produced each alert | Any host with the repo |

## Minimal Script Shape

The script refuses to report a volume reduction without a re-fire result, and it keeps the suppressed events visible instead of dropping them.

```bash
#!/usr/bin/env bash
# tune-gate.sh — shadow differential + re-fire gate for one detection rule.
set -euo pipefail

SH="${SPLUNK_HOST:?set SPLUNK_HOST}"
AUTH="${SPLUNK_AUTH:?set SPLUNK_AUTH as user:pass}"
RULE_ID="${RULE_ID:?set RULE_ID}"
PREDICATE="${PREDICATE:?set PREDICATE, e.g. like(lower(parent_image),\"%veeam%\")}"

q() { # q <search>
  curl -sS -k -u "$AUTH" "https://${SH}:8089/services/search/jobs/export" \
    --data-urlencode "search=$1" --data-urlencode "earliest_time=-14d@d" \
    --data-urlencode "latest_time=@d" --data-urlencode "output_mode=json"
}

# 1. Differential: suppressed vs surviving, per day.
q "index=detections sourcetype=alert:rule_fire rule_id=\"${RULE_ID}\" \
   | eval candidate=if(${PREDICATE},1,0) | bin _time span=1d \
   | stats count AS fired, sum(candidate) AS suppressed by _time \
   | eval surviving=fired-suppressed" > /tmp/diff.json

# 2. Re-fire gate: every labelled positive fixture must still hit.
q "index=detections sourcetype=fixture:positive rule_id=\"${RULE_ID}\" \
   | eval hit=if(isnotnull(matched_rule_id),1,0) \
   | stats sum(hit) AS hits by fixture_id" > /tmp/refire.json

python3 - <<'PY'
import json, sys
rows = lambda p: [json.loads(l)["result"] for l in open(p) if '"result"' in l]
diff, refire = rows("/tmp/diff.json"), rows("/tmp/refire.json")
missed = [r["fixture_id"] for r in refire if float(r["hits"]) == 0]
sup = sum(float(r["suppressed"]) for r in diff)
surv = sum(float(r["surviving"]) for r in diff)
print(f"suppressed={sup:.0f} surviving={surv:.0f}")
if missed:
    sys.exit(f"BLOCK: re-fire regression on fixtures {missed}")
if surv == 0:
    sys.exit("BLOCK: exclusion removes every event; rule is now blind")
print("PASS: volume reduced with coverage preserved")
PY
```

## Notes That Prevent Wrong Runs

- Run the differential on the rule's own search, not over the alert index: an alert index retains what fired, so a predicate applied afterwards classifies events by a rule that did not exist at the time.
- Keep `-maxout 0` and `-preview false` on every measurement run. A capped or previewed result compared against an uncapped one produces a volume delta that belongs to the sampler, not the tune.
- Record the rule version and its deployment timestamp beside every count; without them the differential mixes two populations and no number is attributable.
- The re-fire gate exits non-zero by design. Wire it into the deployment job so a coverage regression fails the change rather than the review.
