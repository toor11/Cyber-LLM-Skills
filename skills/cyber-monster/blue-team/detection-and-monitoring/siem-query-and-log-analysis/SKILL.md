---
name: siem-query-and-log-analysis
description: "Queries SIEM platforms effectively: KQL, SPL and Elastic DSL patterns, field extraction, aggregation and threat hunting queries. Use when investigating or hunting across centralized logs."
family: detection-and-monitoring
tier: core
triggers: ["siem query", "splunk query", "kql", "elastic query", "log analysis"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [siem-query-and-log-analysis-splunk-spl, siem-query-and-log-analysis-kql-and-sentinel, siem-query-and-log-analysis-elastic-and-eql, detection-engineering]
---

# SIEM Query and Log Analysis - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A SIEM query is a three-part contract: a scope (index, table or data stream plus a time range), a field model (the schema the storage layer actually populated), and a reduction operator (filter, aggregate, or sequence). Each part fails separately and looks identical from the outside — an empty result. Scope failures are the loudest: an unbounded or wrong index either times out and returns partials or returns nothing. Field-model failures are the quietest: a field that was never extracted, or that exists under a different name after a schema or pipeline change, produces a genuinely empty filter with no error. Reduction failures are conceptual: `group by` cannot express ordering, and a threshold rule cannot express a sequence, so the query answers a different question than the one asked. Across backends the primitives differ in ways that block transliteration — ECS and OCSF name the same semantic differently, and each platform's aggregation drops rows with null keys under its own rules — so the platform-specific syntax belongs in the variant leaves while the contract stays here.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `splunk-spl` **THEN** switch to [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) (1 hop).
2. **IF** the target specifically involves `kql-and-sentinel` **THEN** switch to [`siem-query-and-log-analysis-kql-and-sentinel`](../siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) (1 hop).
3. **IF** the target specifically involves `elastic-and-eql` **THEN** switch to [`siem-query-and-log-analysis-elastic-and-eql`](../siem-query-and-log-analysis-elastic-and-eql/SKILL.md) (1 hop).
4. **IF** the schema is ECS **THEN** resolve fields against the current ECS release before writing the query, and **IF** it is OCSF **THEN** resolve against the specific event class, because class-scoped names do not exist outside their class.
5. **IF** the question asks for order or a rate **THEN** take the sequence branch; a `group by` aggregate cannot express "then".
6. **IF** the requested window exceeds the data's retention or the aggregation's summarisation coverage **THEN** report `INCONCLUSIVE (Retention Gap)` rather than `Clean/Benign`.
7. **IF** telemetry source covering `KQL` / `SPL` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `siem-query-and-log-analysis-splunk-spl` | [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) | SPL pipeline semantics, `tstats`, transactions |
| Target matches `siem-query-and-log-analysis-kql-and-sentinel` | [`siem-query-and-log-analysis-kql-and-sentinel`](../siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) | KQL operators, `join` kinds, Sentinel tiers |
| Target matches `siem-query-and-log-analysis-elastic-and-eql` | [`siem-query-and-log-analysis-elastic-and-eql`](../siem-query-and-log-analysis-elastic-and-eql/SKILL.md) | EQL sequences, Elasticsearch DSL, piped query language |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Cross-backend scope, field and reduction classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Export and API entry points per backend |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Fields are missing or malformed rather than absent | [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) | Parser and contract defects behind empty queries |

## Procedure

1. **Confirm the scope before writing any operator.** Enumerate the indices, tables or data streams that actually exist and carry data in the window, then bound the query to them with an explicit time range. A scope taken from naming convention is the most common cause of a confident wrong answer.
2. **Choose the reduction branch from the question's shape.** Filter plus projection for single-event facts, `group by` for rates and populations, a sequence operator for ordering, and a summary layer for windows too long to scan raw. Record the branch, because each has a different blind spot.
3. **Define the baseline-versus-probe differential on one key.** Run the identical aggregation over a quiet window and the window under investigation, compare per-key counts, and treat the delta as the finding. Absolute counts mostly measure ingest volume.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the scope returned zero rows for a source that should be present, when a reduction hit a row or time ceiling, when the window crosses retention, or when the decisive field is unmapped for that source. Never soften these into a low-confidence clean.
5. **State what counts as proof.** Proof is the same signal reproduced from a second, independently onboarded source for the same host and principal inside one UTC minute, or the primary query reconciled against a summary-layer count for the same window. One source agreeing with itself is a lead.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Source inventory for the window versus documents returned | scope | Whether an empty result is a real absence or a scope mistake; the gate before every other class |
| `mapped` versus `total` count on the decisive field | field model | Whether the aggregation could have seen the rows it silently dropped as null |
| Per-key count over quiet versus probe window | aggregate differential | A change in rate for one host or principal, independent of total ingest volume |
| Ordered match across two event types within a bounded span | sequence | That the first event preceded the second for the same entity, which no aggregate can encode |
| Summary-layer count reconciled against a raw scan | acceleration | Whether a long-window number reflects events or only summarised windows |
| Row and time ceilings reported by the query job | completeness | Whether the returned set is the answer or the first slice of it |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: the query that answers confidently and wrongly.
search all indices for "4624" | count by user
# No index, no window, no host, no null handling. A timeout returns partial
# results that read exactly like a complete answer, and users with unmapped
# names vanish from the by-clause without a trace.
```

**High-Signal Grounded Artifact:**

```text
# STRONG: scope, key, differential, and an explicit completeness statement.
scope:    index=wineventlog sourcetype=WinEventLog:Security EventCode=4624
window:   baseline -14d@d..-7d@d ; probe -24h@h..@h
key:      coalesce(src, ComputerName) + "|" + coalesce(TargetUserName, "-")
reduce:   count by key, then compare probe against baseline mean and stdev per key
gate:     report count(TargetUserName) vs count(*) so dropped nulls are visible
result:   only keys whose probe count exceeds baseline mean + 3 stdev are findings,
          and the output states the row ceiling that was applied
```

**Why this matters:** the weak form produces a number whose denominator is unknown. The strong form fixes the scope, names the key the claim is about, measures a delta rather than a total, and surfaces the null-drop that would otherwise make the result quietly incomplete.

## When It Is NOT This Issue

- **Wrong scope, not absent data:** querying an index the source does not write to, or a window before the source was onboarded, returns zero with the same shape as a genuine absence. Confirm the source inventory first.
- **Field renamed by a schema migration:** ECS 9.0 removed fields such as `process.pgid` and `service.node.role`, and OCSF class-scoped fields do not resolve outside their class. A query still referencing a removed name returns empty without erroring.
- **Aggregation dropping nulls:** most `group by` implementations discard rows whose key is null, so an unmapped principal disappears rather than appearing as an "unknown" bucket.
- **Row or time ceiling truncation:** result caps and subsearch timeouts return a short answer that looks complete. The job metadata, not the row count, tells you this happened.
- **Retention and summarisation boundaries:** a window that extends past the hot tier, or past the last summarised interval in a summary layer, returns a partial result that reads as a quiet period.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `KQL` / `SPL` was disabled, rotated out, or uncollected.**
- **NEVER present a truncated result, a summary-only zero, or a retention-shortened window as evidence of absence.**
- **NEVER transliterate a query between backends and claim equivalence** — state which backend you ran and what the other would need.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the index, table or data stream was enumerated with data present in the window, not inferred from a name.
- [ ] **Reduction branch chosen:** filter, aggregate, sequence or summary was selected deliberately and its blind spot stated.
- [ ] **Differential defined:** the same aggregation ran over a quiet baseline and the probe window, and the finding is the per-key delta.
- [ ] **Stop condition stated:** scope emptiness, row ceiling, retention boundary and unmapped fields were each cleared or named.
- [ ] **Proof standard met:** two independent sources agree on host and principal inside one UTC minute, or a summary count reconciles against raw.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: siem-query-and-log-analysis
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) - Detection and Monitoring (leaf)
- [`siem-query-and-log-analysis-kql-and-sentinel`](../siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) - Detection and Monitoring (leaf)
- [`siem-query-and-log-analysis-elastic-and-eql`](../siem-query-and-log-analysis-elastic-and-eql/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Contract before syntax:** scope, field model and reduction are platform-neutral; the leaf skills only change how they are spelled. Getting the contract wrong and the syntax right produces a fluent wrong answer.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; all queries here are read-only and must stay inside retention that actually exists.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 31 |
| Distinct dataset sources | 4 |
| Top sources | cyber-security/blue-team__threat-hunting-queries.json (14), CYBER_CPT/L5/ctf_search (12), OffsecCyber (3), cyber-security/CyberSec-Dataset (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
