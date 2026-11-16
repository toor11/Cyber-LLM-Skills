---
name: siem-query-and-log-analysis-elastic-and-eql
description: Elastic and EQL queries. Covers Elasticsearch DSL, KQL and EQL for event correlation and sequence detection. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: detection-and-monitoring
tier: leaf
triggers: ["elastic query", "eql", "kibana query", "elasticsearch dsl"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [siem-query-and-log-analysis, siem-query-and-log-analysis-splunk-spl, siem-query-and-log-analysis-kql-and-sentinel, detection-engineering]
parent: siem-query-and-log-analysis
---

# SIEM Query and Log Analysis Elastic and Eql - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

Elasticsearch exposes three query surfaces over the same indexed documents and they are not interchangeable. The DSL (`_search`) is a request body of `query` plus `aggs` evaluated per shard, so a `terms` aggregation reports the top buckets per shard and then truncates — a field with high cardinality can lose a genuine outlier that a different shard held. EQL (`_eql/search`) is a sequence language over a single event category per query, with `by` joins, `maxspan`, `until` and `runs`, and it returns only the join keys unless you ask for the full events. From Elasticsearch 9.0, EQL defaults `allow_partial_search_results` to `true`, so a shard failure yields partial data with `is_partial` and `shard_failures` rather than an error — a sequence can silently lose its second step. Field names come from the ingest mapping: ECS 9.0 removed `process.pgid`, `process.parent.pgid` and `service.node.role`, so any query still naming them returns empty instead of failing. Data streams and index patterns determine scope; `logs-*` is not a source list.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `siem-query-and-log-analysis-elastic-and-eql` **THEN** start at parent class [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) first.
2. **IF** the question is about order across event types **THEN** take the EQL sequence branch, and **IF** it is about a rate or population **THEN** take the aggregation branch — EQL cannot express a threshold over unrelated events.
3. **IF** the EQL query is security-relevant **THEN** send `allow_partial_search_results=false` explicitly rather than relying on the 9.0 default, and read `is_partial` in the response.
4. **IF** an aggregation's `terms` bucket count matters **THEN** set an explicit `size` and check `sum_other_doc_count`; a nonzero remainder means the tail was cut.
5. **IF** the mapping is ECS **THEN** resolve every field against the current ECS release, and **IF** a name is not in the mapping for that index pattern **THEN** treat the empty result as a mapping defect, not an absence.
6. **IF** telemetry source covering `EQL` or `sequence` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) | General class triage before variant specifics |
| Need sequence, aggregation and mapping queries | [`QUERIES.md`](QUERIES.md) | EQL, DSL and piped-query classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | `_search`, `_eql/search`, `_field_caps` shapes |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Same question in SPL or KQL | [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) | Semantics differ; do not transliterate |

## Procedure

1. **Confirm which index patterns and data streams exist and are receiving.** Read `_cat/indices` or `_data_stream` plus a `_field_caps` call for the fields you intend to use. A field absent from `_field_caps` for that pattern explains an empty filter without any further debugging.
2. **Choose the surface by question shape.** DSL for aggregations and precise filtering, EQL for ordered correlation across event categories, the piped query language for exploratory shaping with joins against lookup indices. Record the surface, because `terms` truncation, EQL partial results and lookup joins have different failure modes.
3. **Define the baseline-versus-probe differential with the same aggregation body.** Run the identical DSL over a quiet 14-day window and the probe window, and compare per-key counts. Two different `size` values make the comparison meaningless, so pin them.
4. **Name the stop condition.** Stop and declare `Inconclusive` when `_shards.failed` is nonzero, when an EQL response has `is_partial` set, when `sum_other_doc_count` shows the tail was cut, when the field is absent from `_field_caps`, or when the window crosses an index lifecycle rollover that dropped a backing index.
5. **State what counts as proof.** Proof is an EQL join whose full events you retrieved and inspected, or a DSL aggregate reconciled against a second data stream for the same host inside one UTC minute. A partial sequence with only join keys is a candidate, not a finding.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `_shards.failed` and `is_partial` on the response envelope | completeness | Whether the returned set is the answer or the subset that survived shard trouble |
| `sum_other_doc_count` on a `terms` aggregation | aggregation truncation | That a `size` limit cut the tail, so an outlier outside the top N is invisible |
| EQL `sequence by host.name with maxspan=` | ordering | The first event preceded the second for one entity; no aggregation can show this |
| `_field_caps` output for the decisive field | mapping | The field exists in that index pattern and is of the type the query assumes |
| `event.category` and `event.dataset` distribution for one source | routing | Which parser and category the events actually landed under, versus where the query looks |
| Full events retrieved after an EQL join | corroboration | Byte counts, process lineage and command line for the matched sequence rather than only its keys |
| Lookup join against a threat-intel or asset index | enrichment | Whether the matching value was already known-bad or belongs to a documented asset owner |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK EQL: relies on the 9.0 default and reads only join keys.
sequence by user.name with maxspan=10m
  [ authentication where event.outcome == "failure" ]
  [ authentication where event.outcome == "success" ]
# allow_partial_search_results defaults to true in 9.0. If one shard holding the
# success events failed, the sequence still returns matches from the survivors,
# and the response is marked is_partial — which nothing here checks.
```

**High-Signal Grounded Detection:**

```text
POST /logs-*/_eql/search?allow_partial_search_results=false
{
  "query": "sequence by user.name, source.ip with maxspan=10m \
     [ authentication where event.outcome == \\"failure\\" ] with runs=5 \
     [ authentication where event.outcome == \\"success\\" and source.ip != null ]",
  "size": 50,
  "event_category_field": "event.category",
  "timestamp_field": "@timestamp",
  "filter": { "range": { "@timestamp": { "gte": "now-24h" } } }
}
# Then re-fetch by _id with _source includes for process/host fields, and only
# treat rows where the success arrived from a different source.ip as findings.
```

**Why this matters:** the weak form can report matches assembled from an incomplete shard set and never says so. The strong form makes shard failure fatal, joins on the address as well as the user, and states the discriminator — a success from a different source — that turns a shape into a finding.

## When It Is NOT This Issue

- **EQL partial results by default:** from 9.0, `allow_partial_search_results` defaults to `true`, so shard failures return data rather than an error. A sequence with `is_partial: true` is unusable as evidence.
- **`terms` aggregation truncation:** the default bucket count cuts long tails silently. A high-cardinality field such as `user.name` or `url.path` loses exactly the rare value you are hunting.
- **ECS field removal:** queries referencing `process.pgid`, `process.parent.pgid` or `service.node.role` return empty on 9.0 mappings with no error, which looks like absence rather than a stale query.
- **Index lifecycle rollover mid-window:** a window that straddles a rollover can miss the older backing index if the pattern or the query targets only current indices.
- **Sequence matching across unrelated sessions:** without a `by` join on a stable entity, EQL will happily pair a failure from one host with a success from another. The join keys define what the sequence actually asserts.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `EQL` was disabled, rotated out, or uncollected.**
- **NEVER present a response with `is_partial` set, a truncated `terms` aggregation, or a stale ECS field's empty result as evidence of absence.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** index pattern or data stream enumerated, and `_field_caps` checked for every decisive field before the query ran.
- [ ] **Surface chosen:** DSL, EQL or piped query selected for the question's shape, with its failure mode named in the output.
- [ ] **Differential defined:** identical aggregation bodies over a quiet and a probe window, with `size` pinned so both tails are cut the same way.
- [ ] **Stop condition stated:** `_shards.failed`, `is_partial`, `sum_other_doc_count`, missing field or rollover was cleared or named.
- [ ] **Proof standard met:** full events retrieved for the matched sequence, or the aggregate reconciled against a second data stream in the same UTC minute.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: siem-query-and-log-analysis-elastic-and-eql
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) - Detection and Monitoring (leaf)
- [`siem-query-and-log-analysis-kql-and-sentinel`](../siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Three surfaces, three failure modes:** `terms` truncation, EQL partial sequences and stale mappings all produce empty-looking results for different reasons. Name which one you hit.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; every call here is a read against `_search`, `_eql/search` or `_field_caps`.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/github_security_md (7), CYBER_CPT/L5/ctf_search (1), CYBER_CPT/blackhills (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
