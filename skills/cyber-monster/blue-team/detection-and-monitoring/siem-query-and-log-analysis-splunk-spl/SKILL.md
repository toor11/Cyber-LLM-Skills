---
name: siem-query-and-log-analysis-splunk-spl
description: "Splunk SPL query patterns. Covers SPL fundamentals for investigation: stats, eval, tstats, lookups and efficient time-bounded searching. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: detection-and-monitoring
tier: leaf
triggers: ["splunk spl", "spl query", "tstats"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [siem-query-and-log-analysis, siem-query-and-log-analysis-kql-and-sentinel, siem-query-and-log-analysis-elastic-and-eql, detection-engineering]
parent: siem-query-and-log-analysis
---

# SIEM Query and Log Analysis Splunk Spl - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

SPL is a pipelined search language executed by a search head against indexers. Everything before the first pipe is the *base search*: its terms are resolved against raw event text plus the indexed default fields (`index`, `host`, `source`, `sourcetype`), so only that segment benefits from tsidx term matching and bloom filters. After the first pipe, streaming and transforming commands operate on fields that were extracted at search time from `props.conf`/`transforms.conf` or produced inline by `rex`/`eval`/`spath`; a field absent from output is therefore an extraction event, not proof the string was never in the event. `tstats` reads accelerated data model summaries instead of raw buckets, and `summariesonly=t` restricts it to summarized time ranges — the cheapest way to count across weeks and the most common source of a false zero when acceleration lags or backfill is incomplete. `stats`, `eventstats`, `transaction` and `join` are the correlation primitives; `stats` destroys raw events and silently drops rows whose by-clause field is null, so null-heavy fields under-count by construction.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `siem-query-and-log-analysis-splunk-spl` **THEN** start at parent class [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) first.
2. **IF** the question needs counts over weeks or the source has an accelerated data model **THEN** take the `tstats` branch, and **IF** acceleration status is unknown **THEN** run `summariesonly=f` next to it and reconcile — never report a `summariesonly=t` zero as absence.
3. **IF** a field is missing from results **THEN** check whether `props.conf`/`transforms.conf` extracts it for that `sourcetype` before concluding the behaviour did not occur; fall back to inline `rex` only to confirm extraction, not to replace onboarding.
4. **IF** the behaviour is a sequence or a rate (many writes then mass delete, spray then success) **THEN** take the `transaction`/`streamstats` branch; a single `stats count by user` cannot express ordering.
5. **IF** the requested window reaches past index retention or a frozen bucket **THEN** report `INCONCLUSIVE (Retention Gap)` rather than `Clean/Benign`.
6. **IF** telemetry source covering `stats` / `eval` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).
8. **IF** required preconditions for `siem-query-and-log-analysis-splunk-spl` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) | General class triage before variant specifics |
| Query must run over 30+ days or high volume | [`QUERIES.md`](QUERIES.md) (`tstats` class) | Summary search avoids raw-bucket scans |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Search CLI, export endpoint, job inspection |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Same question in KQL instead of SPL | [`siem-query-and-log-analysis-kql-and-sentinel`](../siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) | Field and table model differ; do not transliterate |
| Same question in Elastic EQL/DSL | [`siem-query-and-log-analysis-elastic-and-eql`](../siem-query-and-log-analysis-elastic-and-eql/SKILL.md) | Sequence semantics and schema differ |

## Procedure

1. **Prove the evidence source before writing the search.** Enumerate what actually exists with `| metadata type=sourcetypes index=*` and `| metadata type=hosts`, then bound the search to the real `index`/`sourcetype`. A base search built on an assumed sourcetype returns zero rows that look exactly like absence of activity.
2. **Choose the branch from the data's shape, not from habit.** Single-event facts use a scoped base search plus `table`; aggregates use `stats ... by`; long windows on an accelerated model use `tstats`; ordering uses `transaction`/`streamstats`. Record the chosen branch in the output so the reader can judge its blind spots.
3. **Define the baseline-versus-probe differential before reading results.** Run the identical aggregation over a quiet 7–14 day window and over the alert window, then compare per-key counts (`stats count by dest, user, signature`). The differential, not the absolute count, is the finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the differential depends on `summariesonly=t` data, when a subsearch hits its `maxout`/`maxtime` ceiling, when the window crosses retention, or when the decisive field was never extracted for that sourcetype. Do not soften these into "low confidence clean".
5. **State what counts as proof.** Proof is two independently onboarded sources agreeing on the same host and principal inside one UTC minute window, or a `tstats` count reconciled against a raw `stats` count for the same window. A single sourcetype agreeing with itself is a lead, not proof — say which one you have.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `summariesonly=t count from datamodel:Endpoint.Processes` | acceleration | Count came from summaries only; a zero proves the summary range is empty, not that nothing ran |
| `stats count by dest, user, signature` over a matched baseline | aggregate differential | Shift in per-key rate between quiet and alert windows, i.e. a change in behaviour for that principal |
| `transaction host maxspan=10m startswith=...` | sequence | The ordered co-occurrence itself — write burst preceding delete — which no `stats` can encode |
| `rex field=_raw "MessageNumber=(?<mn>\d+)"` | extraction probe | Whether a field exists in raw text but not in the schema, distinguishing parser gap from missing event |
| `eventstats avg(count) as fleet_avg` | contextual baseline | How far one host sits from its own fleet, removing seasonality that a fixed threshold misses |
| `metadata type=sourcetypes` search command | coverage | Which sourcetypes are onboarded at all, i.e. whether "no hits" is even meaningful |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
index=* "4624" | stats count by user
# No sourcetype, no earliest/latest, no by-host dimension.
# Silent failures: null user rows dropped, duplicate ingestion double-counts,
# and index=* scans every bucket so the job times out and returns partials.
```

**High-Signal Grounded Artifact:**

```text
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 earliest=-14d@d latest=@d
| eval k=coalesce(src,ComputerName)."|".coalesce(TargetUserName,"-")
| stats count AS c by k
| eventstats avg(c) AS mu, stdev(c) AS sd
| where c > mu + (3*sd) AND c > 5
| sort - c
# Baseline window and probe window run as two identical searches; the finding is
# the per-key delta, and every row carries the key it was measured on.
```

**Why this matters:** the strong form names the sourcetype and window, keeps the null-bearing keys visible through `coalesce`, and reports a measured delta against the host's own baseline instead of an absolute threshold that only reflects ingest volume.

## When It Is NOT This Issue

- **Double ingestion of one source:** a universal forwarder plus an HEC feed of the same file produces exactly doubled counts and a convincing "spike" with no adversary present. Compare `count by host, source` before believing any volume change.
- **`stats` dropping nulls:** if `TargetUserName` is unmapped for service logons, `stats count by TargetUserName` removes those events entirely and the residual looks like a clean subset. Count `| stats count, count(TargetUserName) AS mapped` and compare.
- **Subsearch truncation:** a `[search ...]` subsearch capped by `maxout`/`maxtime` returns a short allow/deny list, so the outer search quietly misses matches. Correlate with `job.inspector` message counts.
- **Acceleration lag or missing backfill:** `summariesonly=t` over a range that has not been summarized returns zero while raw events exist. Re-run with `summariesonly=f` before drawing any conclusion.
- **Event time versus index time:** `_time` is parsed from the event's own timestamp; late-arriving or badly parsed logs land outside the searched window even though `_indextime` is inside it. Widen with `_indextime` when ingest delay is plausible.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `stats` was disabled, rotated out, or uncollected.**
- **NEVER present a `summariesonly=t` zero, a truncated subsearch, or a retention-truncated window as evidence of absence.**
- **NEVER write `index=*` or an unbounded time range as a production query** — it scans every bucket, times out, and returns partial results that read like completeness.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the `index`/`sourcetype` used in the search was enumerated with `| metadata`, not assumed from naming convention.
- [ ] **Differential defined:** a quiet-window baseline and the probe window were both run, and the reported number is the delta between them.
- [ ] **Stop condition stated:** acceleration, subsearch, extraction and retention ceilings were each explicitly cleared or declared as the reason for `Inconclusive`.
- [ ] **Proof standard met:** either two independent sources agree on host+principal in one UTC minute, or a `tstats` count is reconciled against raw `stats`; the output says which.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: siem-query-and-log-analysis-splunk-spl
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Index/sourcetype, search branch used, UTC baseline and probe windows, acceleration state, uncollected gaps]
- **Behavioral Analysis**: [Per-key differential vs baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Second sourcetype, endpoint or identity evidence checked when the primary search is empty or partial]
- **Containment / Detection / Hardening Action**: [Concrete SPL to deploy, extraction or acceleration fix, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis-kql-and-sentinel`](../siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) - Detection and Monitoring (leaf)
- [`siem-query-and-log-analysis-elastic-and-eql`](../siem-query-and-log-analysis-elastic-and-eql/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Branch first, query second:** the single largest source of wrong SPL conclusions is picking `stats` when the question was about order, or `tstats` when acceleration was never enabled. Declare the branch in the output.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; queries are read-only and must stay inside retention that actually exists.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/ctf_search (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
