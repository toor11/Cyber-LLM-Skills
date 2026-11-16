# Detection Queries and Telemetry Artifacts

> Sub-skill: [`sigma-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Validation, mapping and correlation artifacts owned by `sigma-rule-authoring`. These are checks over the rule corpus itself rather than over telemetry; each class answers one question about whether a rule can work at all. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Spec validity and required metadata

Expected hit: zero errors, and every rule carrying `title`, `logsource`, `detection` and a `condition`. A rule with no category or no condition converts into something unmatchable.

```bash
sigma check rules/
```

```bash
# Rules missing a logsource category, which usually means no pipeline mapping exists.
rg -l --no-heading -g '*.yml' '^detection:' rules/ \
  | xargs -r rg -L '^  category:|^  service:'
```

False-positive note: some legitimate rules use `service:` instead of `category:`; the second check flags those unless both patterns are accepted.

## Class 2 — Pipeline mapping for the intended backend

Expected hit: converted text that references a real source and real fields for that backend. An unmapped category converts into a clause that can never match, and the conversion reports success.

```bash
sigma convert -t splunk -p splunk_windows rules/probe.yml
```

```bash
# The tell: the converted query keeps the generic placeholder instead of a source.
sigma convert -t sentinel -p microsoft_xdr rules/probe.yml | rg -i 'logsource|unknown|placeholder'
```

False-positive note: a backend pipeline that deliberately emits a placeholder for an unsupported modifier is reporting the gap correctly; treat a non-empty match here as the finding, not as noise.

## Class 3 — Field portability

Expected hit: detection blocks referring only to Sigma field names. Vendor names such as `EventID`, `ScriptBlockText` or `requestParameters` bind the rule to one schema.

```bash
# Fields used in detection blocks that are known vendor-specific rather than Sigma names.
rg -o --no-filename -g '*.yml' '^\s{4}[A-Za-z_][A-Za-z0-9_.]*\|?' rules/ \
  | tr -d ' ' | cut -d'|' -f1 | sort | uniq -c | sort -rn | head -40
```

False-positive note: a handful of names are legitimately identical in Sigma and in a vendor schema (`CommandLine`, `Image`); review the tail of the list rather than assuming every match is a defect.

## Class 4 — Correlation structure and meta-field placement

Expected hit: multi-document files where the correlation document is outermost and carries the meta fields, with `group-by` and `timespan` present for every non-metric type.

```yaml
title: Failed Logons Followed by Success On Same Host
id: 3b6a1f42-8f5e-4f0e-9a41-6c2d7e9b1a33
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - Many Failed Logons From One Source
    - Successful Logon From Same Source
  group-by:
    - ComputerName
  timespan: 1h
```

```text
# Structural lint: count '---' separators and confirm the last document holds 'correlation:'.
# A file where a base document carries 'title:' after a correlation document has begun
# is the misplaced-meta case and some tooling resolves the wrong title.
```

False-positive note: a single-document correlation rule legitimately has no separator; only multi-document files are subject to the placement rule.

## Class 5 — Baseline noise before deployment

Expected hit: a small, explainable hit count per host on a quiet corpus. A rule producing thousands of hits against a week of ordinary activity is not ready even if it validates.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-7d@d latest=@d
| search NewProcessName="*\\whoami.exe" OR NewProcessName="*\\systeminfo.exe"
| stats count AS hits, dc(ComputerName) AS hosts BY NewProcessName
| where hits > 50
| eventstats avg(hits) AS mean_hits BY NewProcessName
| eval over_baseline = round(hits / mean_hits, 1)
```

False-positive note: a management server that runs inventory scripts hourly will dominate any process-creation baseline; separate server roles before judging the rule's noise.

## Class 6 — Backend coverage of modifiers

Expected hit: every modifier used by the rule (`contains`, `endswith`, `startswith`, `re`, `base64offset`, `windash`, `cidr`, plus the newer `utf16be`) supported by the target pipeline. An unsupported modifier is silently dropped or approximated.

```bash
sigma list targets
sigma list pipelines
sigma convert -t splunk -p splunk_windows --skip-unsupported rules/
```

False-positive note: `--skip-unsupported` hides the drop rather than reporting it; run once without it to see which rules were affected before deciding to skip.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the conversion command, backend, pipeline name and pySigma version with every deployed rule; a rule without its conversion context cannot be reproduced.
