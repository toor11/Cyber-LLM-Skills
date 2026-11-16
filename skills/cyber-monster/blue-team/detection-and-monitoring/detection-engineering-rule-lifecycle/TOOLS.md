# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`detection-engineering-rule-lifecycle`](SKILL.md) | Family: **Detection and Monitoring**

The lifecycle record is built from five sources: repository history, catalogue metadata, deployed rule text, disposition history, and fixture replay. Commands below are read-only; verify flags against the installed CLI versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `git` | `git log --follow --format='%h %ad %an %s' --date=short -- rules/rule.yml` | Reconstruct the rule's authoring history and last substantive change | Any host with the repo |
| `git` | `git show <commit>:rules/rule.yml` | Retrieve the exact reviewed text for a version, independent of what is deployed | Any host with the repo |
| Splunk REST | `curl -k -u $AUTH "https://$SH:8089/servicesNS/-/-/saved/searches?count=0&output_mode=json"` | Export the deployed catalogue with search text, cron schedule, and disabled state | Search head |
| Splunk REST | `curl -k -u $AUTH "https://$SH:8089/servicesNS/-/-/saved/searches/<name>?output_mode=json"` | Fetch one rule's deployed text for hashing and replay | Search head |
| Microsoft Sentinel API | `curl -sS -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"` | Export deployed analytics rules including `query` and `lastModifiedUtc` | Cross-platform |
| `sigma-cli` | `sigma convert -t splunk -p splunk_windows rules/rule.yml` | Rebuild the query from source to compare against the deployed text | Cross-platform |
| `jq` | `jq -r` with an array filter emitting `rule_id`, `owner`, `review_date` as tab-separated columns | Produce the lifecycle row set from an exported catalogue | Cross-platform |

## Minimal Script Shape

The script produces one lifecycle row per rule and refuses to recommend a transition when the replay could not run.

```bash
#!/usr/bin/env bash
# lifecycle-row.sh — one evidence row per rule: hash, replay, staleness, owner.
set -euo pipefail

CATALOG="${CATALOG:?set CATALOG to a catalogue JSON export}"
FIXTURES="${FIXTURES:-tests/fixtures}"
OUT="${OUT:-/tmp/lifecycle.tsv}"

printf 'rule_id\tdeployed_sha\treplay\tdays_stale\towner\n' > "$OUT"
jq -r '.[] | [.rule_id, .deployed_text, (.owner // ""), (.days_stale // "" | tostring)] | @tsv' "$CATALOG" |
while IFS=$'\t' read -r rule_id text owner stale; do
  sha=$(printf '%s' "$text" | sha256sum | cut -d' ' -f1)
  fixture="${FIXTURES}/${rule_id}.positive.json"
  if [ -z "$text" ]; then
    replay="NO_DEPLOYED_TEXT"
  elif [ ! -f "$fixture" ]; then
    replay="NO_FIXTURE"
  else
    printf '%s\n' "$text" > /tmp/one.spl
    if python3 tests/replay_fixtures.py --query /tmp/one.spl --fixtures "$fixture" --expect match >/dev/null 2>&1; then
      replay="PASS"
    else
      replay="FAIL"
    fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$rule_id" "${sha:0:12}" "$replay" "${stale:-na}" "${owner:-ORPHAN}" >> "$OUT"
done

awk -F'\t' 'NR>1 && ($3!="PASS" || $5=="ORPHAN")' "$OUT"
echo "rows: $(($(wc -l < "$OUT") - 1)) — review the lines above; do not decide on NO_FIXTURE rows"
```

## Notes That Prevent Wrong Runs

- Hash the deployed text, not the repository file. The repository can be correct while production carries a console hotfix, and the hash is what makes the difference visible.
- A `NO_FIXTURE` result is not a pass. Author the fixture before choosing a transition, or the decision rests on nothing.
- `git log --follow` is required for renamed rule files; without it the history appears to begin at the rename and the real authoring date is lost.
- Catalogue exports vary in field names between platforms (`lastModifiedUtc` versus a Splunk `updated` epoch); normalise before diffing timestamps.
- Replays against expanded macros only. An unexpanded search text fails for reasons unrelated to the rule's logic.
