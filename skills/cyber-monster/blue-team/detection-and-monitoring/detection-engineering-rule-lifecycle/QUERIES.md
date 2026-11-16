# Detection Queries and Telemetry Artifacts

> Sub-skill: [`detection-engineering-rule-lifecycle`](SKILL.md) | Family: **Detection and Monitoring**

Lifecycle queries read the rule catalogue, the disposition store, the sensor health stream, and the fixture replay output. None of them read security telemetry for adversary evidence. For rule metadata shape and conversion mechanics see [`detection-engineering`](../detection-engineering/SKILL.md) and [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md).

## Class 1 — Staleness clock

Expected hit: one row per rule with days since last disposition and days since review. Rules crossing their review interval with no dispositions are the population the retirement test exists for.

```spl
index=detections sourcetype="rule:catalog" earliest=-1d@d latest=@d
| stats latest(owner) AS owner, latest(review_date) AS reviewed, latest(attack_id) AS attack_id by rule_id
| join type=left max=1 rule_id
    [ search index=detections sourcetype="alert:disposition" earliest=-90d@d latest=@d
      | stats max(_time) AS last_disposition, count AS judged by rule_id ]
| eval days_stale = round((now() - last_disposition)/86400, 0)
| eval days_since_review = round((now() - reviewed)/86400, 0)
| where isnull(last_disposition) OR days_since_review > 180
| sort - days_stale
```

False-positive note: a rule deployed last week has no disposition history by design; compare against its deployment date before calling it stale.

## Class 2 — Orphaned ownership

Expected hit: rules whose `owner` is empty, a group mailbox nobody reads, or an account no longer present in the directory. Orphaned rules decay without anyone noticing.

```spl
index=detections sourcetype="rule:catalog" earliest=-1d@d latest=@d
| stats latest(owner) AS owner by rule_id
| join type=left owner
    [ search index=identity sourcetype="directory:user" earliest=-1d@d latest=@d
      | stats latest(enabled) AS enabled, latest(department) AS department by samaccountname ]
| where isnull(enabled) OR enabled=="false" OR isnull(owner) OR owner==""
| sort owner
```

False-positive note: a service account that owns rules legitimately has no interactive sign-in record; resolve the owner against the directory rather than against sign-in telemetry.

## Class 3 — Fixture replay against the deployed text

Expected hit: `PASS` for every rule whose artifact still exists on the current sensor build. A `FAIL` with a healthy sensor is a broken rule; a `FAIL` with a missing artifact is an unmaintainable one.

```bash
set -eu -o pipefail
RULE_ID="${RULE_ID:?set RULE_ID}"
deployed=$(curl -sS -k -u "$AUTH" "https://$SH:8089/servicesNS/-/-/saved/searches/${RULE_ID}?output_mode=json" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["entry"][0]["content"]["search"])')
printf '%s\n' "$deployed" | sha256sum
printf '%s\n' "$deployed" > /tmp/deployed.spl
test -s /tmp/deployed.spl || { echo "NO_DEPLOYED_TEXT"; exit 3; }
python3 tests/replay_fixtures.py --query /tmp/deployed.spl \
  --fixtures "tests/fixtures/${RULE_ID}.positive.json" --expect match
```

False-positive note: the saved-search API returns the search with macros unexpanded; a replay of the unexpanded text fails for reasons unrelated to the rule, so expand macros first or replay the compiled artefact.

## Class 4 — Duplicate coverage by analytic

Expected hit: two or more rules mapping to the same strategy/analytic pair with overlapping platform and host scope. Rank them by sampled precision before consolidating.

```spl
index=detections sourcetype="rule:catalog" earliest=-1d@d latest=@d
| stats values(rule_id) AS rules, dc(rule_id) AS n by analytic_id, platform
| where n > 1 AND analytic_id!="-"
| join type=left analytic_id
    [ search index=detections sourcetype="alert:disposition" earliest=-29d@d latest=@d
      | eval fp=if(disposition=="false_positive",1,0)
      | stats sum(fp) AS fp, count AS judged by rule_id ]
| sort - n, platform
```

False-positive note: two rules for the same analytic on different platforms are complementary, not duplicates; require the platform column to match before treating them as consolidation candidates.

## Class 5 — Mapping validity after a framework release

Expected hit: zero unresolvable references. After a restructure, several technique identifiers resolve to a merged parent, and a rule referencing the retired identifier looks valid in the catalogue while pointing at nothing.

```spl
index=detections sourcetype="rule:catalog" earliest=-1d@d latest=@d
| stats latest(attack_id) AS attack_id by rule_id
| join type=left attack_id
    [ search index=framework sourcetype="attack:technique" earliest=-1d@d latest=@d
      | stats latest(revoked) AS revoked, latest(deprecated) AS deprecated, latest(new_id) AS new_id by attack_id ]
| where revoked=="true" OR deprecated=="true" OR isnull(new_id) AND isnull(revoked)
| eval action = if(isnotnull(new_id), "re-map to ".new_id, "review for retirement")
| sort action
```

False-positive note: a framework snapshot older than the release that introduced the merge shows no `new_id`; refresh the framework table before concluding a mapping is unrecoverable.

## Class 6 — Logsource health behind a silent rule

Expected hit: an obvious separation between rules that are quiet with a healthy logsource and rules whose logsource stopped delivering. The second group is a pipeline outage, not a rule-lifecycle question.

```spl
index=* earliest=-24h@h latest=now
| eval st = coalesce(sourcetype, "unknown")
| stats count AS events, latest(_time) AS last_event by st, host
| eval hours_silent = round((now() - last_event)/3600, 1)
| where hours_silent > 6
| stats sum(events) AS events, dc(host) AS hosts, max(hours_silent) AS worst by st
| sort - worst
```

False-positive note: genuinely low-volume sources such as a monthly batch feed are silent for long stretches; pair the silence with the source's expected cadence before filing an outage.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the transition, its evidence, and the next review date on the rule itself; a decision held only in a meeting note is not a lifecycle record.
