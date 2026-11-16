# Detection Queries and Telemetry Artifacts

> Sub-skill: [`mitre-attack-mapping`](SKILL.md) | Family: **Detection and Monitoring**

Mapping and coverage queries owned by `mitre-attack-mapping`. These treat rules, layers and the ATT&CK catalogue as data and join them; they do not detect adversary activity directly. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Rule-to-technique inventory and unmapped rules

Expected hit: every enabled rule carries at least one `attack.tXXXX` tag, and the tag resolves in the pinned catalogue version. Rules with no tag, or with an ID that does not resolve, are unmapped.

```spl
| inputlookup detection_rules.csv
| eval tags_coalesce = coalesce(attack_tags, "NONE")
| makemv delim="," tags_coalesce
| mvexpand tags_coalesce
| where tags_coalesce="NONE" OR NOT match(tags_coalesce, "^attack\.t\d{4}(\.\d{3})?$")
| stats count BY rule_name, tags_coalesce
| eventstats sum(count) AS untagged_total
| eval untagged_pct = round(100*count/untagged_total, 1)
```

False-positive note: a rule that legitimately detects an anomaly rather than a technique has no honest mapping; tag it as unmapped-by-design instead of forcing the nearest technique.

## Class 2 — Catalogue resolution against a pinned version

Expected hit: every referenced ID present in the release you pinned, with tactic assignment matching that release. IDs missing here are the pre-v19 casualties such as `T1562` and `T1562.001`.

```bash
# Resolve every ID in a Navigator layer against the pinned enterprise bundle.
jq -r '.techniques[].techniqueID' layer.json | sort -u > /tmp/used.txt
jq -r '.objects[] | select(.type=="attack-pattern") | .external_references[0].external_id' \
  enterprise-attack-v19.json | sort -u > /tmp/known.txt
comm -23 /tmp/used.txt /tmp/known.txt   # IDs used but not in this release
```

False-positive note: revoked and deprecated techniques remain in the STIX bundle with `revoked: true`; they resolve as known but must not be counted as covered. Filter on the revocation flag, not on presence alone.

## Class 3 — Tagged versus validated coverage

Expected hit: two sets — techniques with a deployed rule, and techniques whose rule fired against a real or emulated instance. The difference is the honest gap.

```spl
| inputlookup technique_relevance.csv
| join type=left technique_id
    [ search index=detection_validation sourcetype=emulation_result earliest=-90d@d
      | stats latest(fired) AS fired, latest(ttfa_seconds) AS ttfa BY technique_id ]
| eval tier = case(fired="true", "validated", isnotnull(deployed_rule), "deployed", true(), "gap")
| stats dc(technique_id) AS techniques BY tier
| eventstats sum(techniques) AS total
| eval pct = round(100*techniques/total, 1)
```

False-positive note: a rule that fires only on a specific filename or hash passes validation once and fails the next emulation with a renamed artefact; validation must be re-run, not carried forward.

## Class 4 — Data component availability per mapped technique

Expected hit: for each mapped technique, the Data Component its Detection Strategy names is collected and passing its contract gates. Any technique whose component is missing is nominal coverage.

```kql
let mapped = _GetWatchlist('attack_mapping')
| project technique_id, detection_strategy, data_component, source_table;
let flowing = union withsource=tbl *
  (SecurityEvent | where TimeGenerated > ago(7d) | summarize n=count() by tbl)
  (SysmonEvent  | where TimeGenerated > ago(7d) | summarize n=count() by tbl)
  (DeviceProcessEvents | where TimeGenerated > ago(7d) | summarize n=count() by tbl);
mapped
| join kind=leftouter (flowing) on $left.source_table == $right.tbl
| extend status = iff(isnull(n) or n < 10, "nominal-coverage", "collected")
| summarize techniques=count() by status
```

False-positive note: a low-volume table can be genuinely quiet rather than uncollected; confirm with the ingestion heartbeat before downgrading a mapping.

## Class 5 — Granularity conflicts

Expected hit: techniques where two sub-techniques are claimed by rules that consume the same single observable. Those claims cannot both be defended from that field set.

```text
# Manual review query: same observable, multiple sub-technique claims.
# For each (source_table, key_field) pair, list the distinct sub-technique IDs
# tagged by rules that read only that field. Two or more IDs with one observable
# field is the conflict set.
source_table | key_field        | sub_techniques_claimed
-------------|------------------|--------------------------------------
WinEventLog  | ScriptBlockText  | T1059.001, T1027, T1140
WinEventLog  | ParentImage      | T1569.002, T1055
```

False-positive note: some pairs are legitimately distinguishable by a second field in the same event (for example `CommandLine` plus `ParentImage`); confirm the rule actually reads both before flagging.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Pin the ATT&CK release and Navigator layer schema version in the layer `description`; an unpinned layer cannot be compared with next quarter's.
