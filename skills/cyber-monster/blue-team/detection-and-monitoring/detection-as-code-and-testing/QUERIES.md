# Detection Queries and Telemetry Artifacts

> Sub-skill: [`detection-as-code-and-testing`](SKILL.md) | Family: **Detection and Monitoring**

Queries here answer questions about the detection pipeline itself: what shipped, whether it matches the repository, and whether the fixture set still exercises the rule. They read a detection-metadata index and the backend's rule inventory, not security telemetry. For query-language mechanics see [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md).

## Class 1 — Source-to-deployment provenance

Expected hit: one row per rule with a commit hash, a build artefact path, and a deployment timestamp. Rules with a source but no artefact, or a deployment timestamp that predates the artefact, are unprovenanced and cannot be reviewed.

```spl
index=detections sourcetype="pipeline:build" earliest=-30d@d latest=@d
| stats latest(commit) AS commit, latest(build_time) AS built, values(backend) AS backends by rule_id
| join type=left max=2 rule_id
    [ search index=detections sourcetype="pipeline:deploy" earliest=-30d@d latest=@d
      | stats latest(deploy_time) AS deployed, latest(commit) AS deployed_commit by rule_id ]
| where isnull(deployed) OR deployed < built OR commit != deployed_commit
| sort rule_id
```

False-positive note: a rule deployed before the pipeline existed has no build record by design; exclude a documented legacy set rather than treating every pre-pipeline rule as broken.

## Class 2 — Fixture coverage per rule

Expected hit: at least one positive and one negative fixture for every deployed rule, plus a boundary fixture wherever a numeric threshold exists. A rule with only a positive fixture is untested against noise.

```spl
index=detections sourcetype="test:fixture_catalog" earliest=-1d@d latest=@d
| stats dc(eval(if(kind=="positive",fixture_id,null))) AS positives,
        dc(eval(if(kind=="negative",fixture_id,null))) AS negatives,
        dc(eval(if(kind=="boundary",fixture_id,null))) AS boundaries by rule_id
| where positives == 0 OR negatives == 0
| sort positives, negatives
```

False-positive note: a fixture catalogue that is generated at test time rather than indexed will appear empty; confirm the catalogue source before reporting a coverage hole.

## Class 3 — Negative-fixture firing (the precision gate)

Expected hit: zero rows. Any rule whose negative fixture produced a match is shipping a precision defect, regardless of how well its positive fixture behaves.

```spl
index=detections sourcetype="test:fixture_replay" earliest=-2d@d latest=@d
| where kind=="negative" AND matched==1
| stats count AS unexpected_matches, values(fixture_id) AS fixtures by rule_id, backend
| sort - unexpected_matches
```

False-positive note: a negative fixture built from a different schema version than the rule's logsource will match for the wrong reason; verify the fixture parsed before treating a match as a rule defect.

## Class 4 — Correlation window assertions

Expected hit: the in-window fixture pair fires and the out-of-window pair does not. A rule where both pairs fire has a `timespan` that is not enforced on that backend.

```spl
index=detections sourcetype="test:correlation_replay" earliest=-2d@d latest=@d
| stats max(eval(if(pair=="inside",matched,0))) AS inside_matched,
        max(eval(if(pair=="outside",matched,0))) AS outside_matched
        by rule_id, backend
| where inside_matched==1 AND outside_matched==1
```

False-positive note: some backends implement correlation at search time rather than at ingest, so an out-of-window pair can match when the query window is wider than the rule's `timespan`; read the compiled query before calling it a defect.

## Class 5 — Production drift against the built artefact

Expected hit: zero rows where the deployed text differs from the artefact built from the current commit. Drift here is usually a console hotfix during an incident.

```spl
index=detections sourcetype="pipeline:drift_check" earliest=-1d@d latest=@d
| eval normalised_deployed = trim(lower(deployed_text))
| eval normalised_built = trim(lower(built_text))
| where normalised_deployed != normalised_built
| stats count by rule_id, backend, deployed_commit
| sort rule_id
```

False-positive note: whitespace and comment differences are common after backend normalisation; compare a canonicalised form (comments stripped, whitespace collapsed) or the check will flag every rule.

## Class 6 — Historical sample regression

Expected hit: a hit-count delta bounded to the intended change. A rule whose hits collapse to zero on the sample has lost its selection, even if every fixture still passes.

```kql
let candidate = DetectionSample
| where Timestamp between (ago(30d) .. ago(1d))
| where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete"
| summarize candidate_hits=count() by DeviceId;
let deployed = DetectionSample
| where Timestamp between (ago(30d) .. ago(1d))
| where ProcessCommandLine has_any ("vssadmin","wbadmin") and ProcessCommandLine has "delete"
| summarize deployed_hits=count() by DeviceId;
candidate
| join kind=fullouter deployed on DeviceId
| extend delta = candidate_hits - deployed_hits
| where delta < 0 or candidate_hits == 0
```

False-positive note: the sample table's retention may be shorter than 30 days; confirm the earliest row before treating a zero as a rule regression rather than a retention boundary.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Block promotion on any negative-fixture match, any correlation-window failure, and any drift row; a green lint stage alone is not a gate.
