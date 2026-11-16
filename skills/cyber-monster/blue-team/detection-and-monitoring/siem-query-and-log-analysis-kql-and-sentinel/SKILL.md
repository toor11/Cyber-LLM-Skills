---
name: siem-query-and-log-analysis-kql-and-sentinel
description: "KQL and Microsoft Sentinel queries. Covers KQL for Defender and Sentinel: summarize, join, extend and working with security alert tables. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: detection-and-monitoring
tier: leaf
triggers: ["kql", "sentinel query", "defender query", "kusto"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [siem-query-and-log-analysis, siem-query-and-log-analysis-splunk-spl, siem-query-and-log-analysis-elastic-and-eql, detection-engineering]
parent: siem-query-and-log-analysis
---

# SIEM Query and Log Analysis Kql and Sentinel - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

KQL is a tabular pipeline: each operator consumes a table and emits a table, and the row count is decided by the *first* operator that reduces it, not by the last. `summarize` is the only operator that changes granularity, so a query that summarizes before filtering has already discarded the detail the filter needed. `join` defaults to `innerunique`, which de-duplicates the left side on the join key before matching — a subtle source of undercount when the left side legitimately has several rows per key; `kind=` must be stated. Time filtering belongs in the `where` clause on `TimeGenerated` (analytics tier) because ingestion-time fields do not exist for every source. In Sentinel 2026 the storage tier decides what a query can even see: Defender XDR advanced hunting tables ingested lake-only are invisible to analytics rules, hunting queries, workbooks and playbooks, so a rule referencing one returns nothing while the data exists in the lake, and lake-tier interactive KQL runs through Advanced Hunting with row, size and timeout limits.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `siem-query-and-log-analysis-kql-and-sentinel` **THEN** start at parent class [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) first.
2. **IF** a table may be lake-only **THEN** check its tier before writing an analytics rule against it; a lake-only table is invisible to Sentinel rules and the rule fails silently rather than erroring.
3. **IF** the query joins two tables **THEN** state the `kind=` explicitly; the default `innerunique` drops duplicate left-side keys and undercounts without warning.
4. **IF** the question is a sequence ("then") **THEN** use `serialize` with `prev()` or a window function, not `summarize`; **IF** it is a rate or population **THEN** `summarize` is correct.
5. **IF** the query runs against the lake tier **THEN** keep it inside the row, size and timeout limits, and prefer scheduled KQL jobs or summary rules for anything recurring.
6. **IF** telemetry source covering `summarize` or `join` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) | General class triage before variant specifics |
| Need summarization, join and sequence queries | [`QUERIES.md`](QUERIES.md) | KQL classes including tier and join-kind checks |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Query API, `az monitor`, `Sentinel` ingestion inspection |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Same question in SPL or EQL | [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) | `join` semantics differ fundamentally; do not transliterate |

## Procedure

1. **Confirm table availability and tier before writing an operator.** List the tables with data in the window and, for each, whether it is analytics-tier or lake-only. A lake-only table answers in Advanced Hunting and not in a Sentinel rule, which changes where the detection must live.
2. **Choose the granularity point deliberately.** Decide where `summarize` sits: after filtering and after any `extend` that the filter depends on, and before the projection that would drop the discriminating column. Placing it early is the most common silent undercount.
3. **Define the baseline-versus-probe differential with the same summarize shape.** Compute the per-key count over a quiet 14-day window and the probe window with identical `bin()` size and identical `kind=` on any join. A different bin size makes the two windows incomparable.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the table is lake-only and the consumer is an analytics rule, when the lake query exceeds its row or timeout limit, when a join's `innerunique` default has removed legitimate duplicate keys, when the analytic-tier retention ends inside the window, or when an `extend` produced nulls that the filter then silently dropped.
5. **State what counts as proof.** Proof is the same finding reproduced from a second table for the same device and account inside one UTC minute, or a `summarize` result reconciled against a row-level query that returns the individual events. Aggregation without a row-level confirmation is a lead.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Table inventory with tier per table | scope and tier | Whether the detection can live in an analytics rule at all, or must be a Defender-side or lake job |
| `summarize count() by DeviceId, bin(TimeGenerated, 1d)` | aggregation | Per-entity rate with an explicit granularity point, comparable across windows |
| `join kind=leftouter` with a stated kind | join correctness | That duplicate left-side keys were preserved rather than collapsed by `innerunique` |
| `serialize` with `prev()` over an ordered partition | sequence | That one event preceded another for the same entity, which `summarize` cannot show |
| `countif(isempty(Field))` next to `count()` | field model | The null share the later filter would drop without any error |
| Lake-tier query duration and row count against the documented limits | tier capacity | Whether the query completed or was cut, and therefore whether the answer is partial |
| `SigninLogs` result reconciled against `DeviceLogonEvents` | corroboration | That identity-plane and endpoint-plane evidence agree on the same account and minute |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```kql
// WEAK: summarizes away the entity, then filters on it.
SigninLogs
| where TimeGenerated > ago(7d)
| summarize count() by ResultType
| where ResultType != 0 and count_ > 100
// Join is never stated, the entity is gone, and a "spike" here is just
// the estate's total failed sign-ins for a week.
```

**High-Signal Grounded Detection:**

```kql
// STRONG: filter, keep the entity, aggregate at a stated grain, join explicitly.
let baseline = SigninLogs
| where TimeGenerated between (ago(14d) .. ago(1d))
| where ResultType != 0
| summarize c = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1d)
| summarize mu = avg(c), sd = stdev(c) by UserPrincipalName, IPAddress;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0
| summarize probe = count(), first_seen = min(TimeGenerated) by UserPrincipalName, IPAddress
| join kind=inner baseline on UserPrincipalName, IPAddress
| where probe > mu + 3 * sd and probe > 5
| project UserPrincipalName, IPAddress, mu, sd, probe, first_seen
```

**Why this matters:** the weak form aggregates away the principal and the address, so nothing in the output can be actioned and the threshold measures estate-wide volume. The strong form keeps the entity through the aggregation, states the join kind, and compares each principal-and-address pair against its own history.

## When It Is NOT This Issue

- **Lake-only table queried by an analytics rule:** the rule returns nothing while the data exists. Nothing errors, and the table looks healthy in Advanced Hunting.
- **`innerunique` join undercount:** the default de-duplicates the left side on the join key. Two legitimate rows per key become one, and any subsequent `count()` is wrong by construction.
- **`summarize` before the filter that needs detail:** once granularity is reduced the discarded columns are unrecoverable, and the filter silently matches nothing rather than erroring.
- **Ingestion latency inside a tight window:** analytics-tier tables can lag by minutes, so a `ago(5m)` window is structurally incomplete for many sources. Confirm with the ingestion-time distribution.
- **Lake-tier query limits:** row, size and timeout ceilings truncate a broad historical query. A returned subset is not the population, and the limit does not always present as an error.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `summarize` or `join` was disabled, rotated out, or uncollected.**
- **NEVER present a lake-only table's empty analytics-rule result, a truncated lake query, or an `innerunique` undercount as evidence of absence.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the tables were listed with data in the window, and each table's analytics-versus-lake tier was checked.
- [ ] **Granularity chosen:** the `summarize` position was decided against the filter's needs, and every `join` states its `kind`.
- [ ] **Differential defined:** identical summarize shape over a quiet and a probe window, with matching `bin()` size and join kind.
- [ ] **Stop condition stated:** lake-only mismatch, query limits, `innerunique` collapse, retention boundary or null-producing `extend` was cleared or named.
- [ ] **Proof standard met:** the aggregate is reconciled with a row-level query, or a second table agrees on device and account inside one UTC minute.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: siem-query-and-log-analysis-kql-and-sentinel
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
- [`siem-query-and-log-analysis-elastic-and-eql`](../siem-query-and-log-analysis-elastic-and-eql/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Granularity is a decision, not an afterthought:** where `summarize` sits determines which questions the rest of the query can still answer. Place it deliberately and say where.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; the Query API is read-only and `_GetWatchlist` does not mutate state.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/ctf_search (1), CYBER_CPT/oxdf (1), CYBER_CPT/ctf_wiki (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
