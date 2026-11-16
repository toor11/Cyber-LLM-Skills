# Operational Triage and Response Playbook

> Sub-skill: [`siem-query-and-log-analysis-splunk-spl`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `siem-query-and-log-analysis-splunk-spl`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- An alert fired from a saved search and the analyst must decide whether the count is real or an artefact of the search itself.
- A hunt request names a behaviour but not an index, sourcetype or field, so the source must be discovered before the question can be answered.
- Two queries over the same window disagree, and the disagreement must be attributed to acceleration, extraction, truncation or retention.
- A detection needs re-tuning after a change to `props.conf`, a data model, or the index retention policy.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Differential holds against a quiet-window baseline and a second independently onboarded sourcetype agrees on host and principal | Confirmed Malicious | Preserve the raw events for the window with a scheduled export, then hand to IR with the two source names and the UTC minute |
| Differential exists in one sourcetype only, or appears only after a `rex` fallback | Inconclusive (Extraction Gap) | Fix the `props.conf`/`transforms.conf` extraction for that sourcetype, re-run, and re-score; do not escalate on a `rex`-only signal |
| `tstats summariesonly=t` returns zero while `summariesonly=f` returns rows | Inconclusive (Acceleration Gap) | Report the acceleration range that is missing, not a clean result; re-run the window after backfill |
| Counts change materially when `-maxout` or subsearch limits are relaxed | Inconclusive (Truncation) | Re-dispatch uncapped or convert the subsearch to a lookup table before interpreting |
| Requested window precedes the index's frozen buckets or the search head's retention | Inconclusive (Retention Gap) | State the earliest searchable timestamp explicitly; escalate to whoever owns backup or archive retrieval |
| Matches a documented change ticket, scanner window, or a known double-ingested source | Benign Baseline | Record the ticket or duplicate feed, scope any exclusion to that host/principal, and re-measure precision |

## Containment and Recovery

1. **Preserve before mutating:** export the raw events for the confirmed window (`output_mode=json`, uncapped) and record the export's SHA-256 beside the search string and the time range used to produce it. A finding without its query is not reproducible.
2. **Fix the pipeline before the rule:** if the differential depended on a missing extraction, an unaccelerated range or a truncated subsearch, correcting the pipeline is the remediation — tightening the threshold on top of a broken pipeline only hides the problem.
3. **Check blast-radius side effects of any exclusion:** a filter added to reduce noise must be scoped to a host, principal or signature. An index-wide `NOT` clause is a visibility outage that will not announce itself.
4. **Re-validate after the change:** one positive replay plus a full baseline window, comparing the same per-key metric that triggered the original alert. Report the before and after counts, not just "tuned".
