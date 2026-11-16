---
name: log-source-onboarding-and-parsing
description: "Onboards log sources correctly: identifying required event types, parsing and normalization, field mapping to a schema and validating coverage. Use when adding telemetry to a detection pipeline."
family: detection-and-monitoring
tier: core
triggers: ["log onboarding", "log parsing", "normalization", "field mapping", "telemetry coverage"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Log Source Onboarding and Parsing - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

Onboarding is a contract with three separately failable stages: the producer emits the event, the transport delivers it without loss, and the parser maps its native fields onto the schema the detections read. Most "the rule never fires" incidents fail at the third stage while the first two look healthy — the source is flowing, the index is growing, and the field the rule keys on is simply never populated because a parser branch for that event type was never written. Normalization adds a second failure mode: mapping to ECS, OCSF or a vendor CIM renames semantics, so `source.ip` in ECS and `src_endpoint.ip` in OCSF describe the same thing only if a mapping exists for that specific producer. Preconditions are an identified event set with a documented native format, a schema target chosen before parsing begins, and a measurable quality gate (freshness, null-rate per required field, volume against producer-side counters) that a source must pass before any detection may claim coverage on it.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the required event type is not enabled at the producer (audit subcategory off, Sysmon config omitting the EventID, cloud trail not capturing management or data events) **THEN** stop — parser work cannot substitute for absent events, and the result is `INCONCLUSIVE (Telemetry Gap)`.
2. **IF** the destination schema is ECS **THEN** resolve every rule field against the current ECS release and confirm removed fields are not referenced; **IF** it is OCSF **THEN** resolve against the event class you selected, because field names are class-scoped and `raw_data_hash` lives on `base_event`.
3. **IF** the source is cloud **THEN** split control-plane from data-plane ingestion; most providers enable the control plane by default and require a separate, per-bucket or per-store data-event subscription that is usually off.
4. **IF** a required field is null in more than a small percentage of events **THEN** treat the source as failing its contract and block any detection that depends on it, rather than writing a fallback regex.
5. **IF** events arrive later than the detection window depends on **THEN** record the measured ingest delay and widen the rule window or switch to an event-time field that the producer sets.
6. **IF** telemetry source covering `parser` or `normalization` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parser probes, null-rate and freshness queries | [`QUERIES.md`](QUERIES.md) | Contract gates as executable checks |
| Need collector and CLI syntax | [`TOOLS.md`](TOOLS.md) | OpenTelemetry collector, `logstash`, `fluent-bit`, `tcpdump` verification |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Handoff when a gap is found mid-incident |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Same fields, different query language | [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) | Class methodology before platform syntax |
| Rule that must survive schema drift | [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) | Field mapping expressed once, converted per backend |

## Procedure

1. **Confirm the evidence source end to end before parsing anything.** Establish three separate facts: the producer setting that emits the event, a delivery count from the transport (forwarder queue, collector `sent`/`dropped` metrics), and a document count in the destination for the same window. Numbers must reconcile within an acceptable margin; if they do not, the gap is transport, not parsing.
2. **Choose the branch: sample-first versus contract-first.** For a new source, capture a raw sample and derive the parse from actual bytes. For a known source that regressed, diff the current mapping against the last known-good one before touching the pipeline — most regressions are an upstream format change, not a parser bug.
3. **Define the baseline-versus-probe differential.** Compute per-field null-rate and per-`event.type` daily volume over a quiet 7–14 day window, then again over the window under investigation. A field that was 2% null and is now 90% null is the finding; a field that was always null was never onboarded.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the producing setting cannot be verified, when the transport shows dropped events you cannot bound, when the schema target lacks a field for the required semantic (there is no honest mapping), or when the source's retention in the destination is shorter than the question's window.
5. **State what counts as proof.** Proof is a producer-side artefact (a known event you generated, or a producer counter) matched by a destination document carrying every required field with a non-null value, plus a rule that fires on that document. Volume without field completeness is delivery, not onboarding.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Per-field null-rate over baseline versus probe window | schema contract | Which fields stop being populated for that producer, exposing parser drift that volume alone hides |
| Producer counter compared with destination document count for the same hour | reconciliation | Transport loss or duplication, separating delivery failure from parsing failure |
| `event.dataset` / `observer.vendor` cardinality spike | dataset routing | A new or renamed dataset appeared, meaning the parser assignment fell through to a default branch |
| Raw-sample reparse into the target schema in a test pipeline | mapping validation | The mapping is arithmetically correct for the actual bytes, independent of production routing |
| `ingest pipeline` error documents in a dead-letter index | pipeline health | Records that were rejected rather than parsed, which silently never reach a detection |
| Freshness as destination-time minus producer-time percentile | latency | Whether late arrival pushes events outside the rule's window, making a rule blind to slow sources |
| OCSF `class_uid` distribution across one source | normalization | Whether the producer's events all collapsed into one class, a sign the class-selection filter is too broad |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK ONBOARDING:
# "We ingest CloudTrail, so we have AWS coverage."
# Volume is green, the index has documents, and the rule author assumes
# eventName and userIdentity.arn are populated for every record.
```

**High-Signal Grounded Artifact:**

```yaml
# CONTRACT GATE (checked before any rule claims coverage on this source)
source: aws.cloudtrail
schema_target: ocsf_1_6
required_fields:
  - class_uid              # must be 3005 API Activity for management events
  - actor.user.name
  - api.operation
  - src_endpoint.ip
gates:
  freshness_p95_minutes: 15
  null_rate_max: 0.02
  producer_reconciliation: within_5_percent
on_failure: mark rules on this source as INCONCLUSIVE (Telemetry Gap)
```

**Why this matters:** the weak form treats ingest volume as coverage. The strong form names the schema class the events must land in, lists the exact fields detections will read, and defines numeric gates — so an empty result can be attributed to a specific broken gate instead of being reported as an absence of activity.

## When It Is NOT This Issue

- **Volume growth from a second shipping path:** a forwarder and a collector both tailing the same file doubles documents with no parser change. Reconcile `count` by `host` and `source` before blaming the parser.
- **New dataset with no mapping assigned:** vendors rename datasets between agent versions, and the new name falls to a default parser that emits a `message` field only. Field null-rate spikes while volume stays flat.
- **Time-zone and format drift in the producer:** an appliance firmware update switching a timestamp to local time moves events outside the window. Freshness looks negative or wildly positive; inspect the raw sample before editing the pipeline.
- **Legitimate sparse fields:** `file.hash.sha256` is null for every event type that has no file, so a high null-rate on a legitimately conditional field is expected. Compute null-rate only over the event types where the field is contractually required.
- **Retention shorter than the question:** a 30-day hot tier queried over 60 days returns a clean-looking half-window. This is a retention ceiling, not a parsing defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `parser` was disabled, rotated out, or uncollected.**
- **NEVER invent vendor field names, dataset names, or parser module paths** — read them from a captured sample or the installed parser inventory.
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** producer setting, transport counters and destination document count were all three observed and reconciled, not inferred from one another.
- [ ] **Mapping branch chosen:** sample-first or contract-first was selected and stated, with the schema target and its version named.
- [ ] **Differential defined:** per-field null-rate and per-event-type volume were compared between a quiet baseline window and the probe window.
- [ ] **Stop condition stated:** missing producer setting, unbounded transport loss, absent schema field or short retention was named as the `Inconclusive` reason where it applied.
- [ ] **Proof standard met:** a generated or counter-verified event appears in the destination with every required field non-null and a rule fires on it.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: log-source-onboarding-and-parsing
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`alert-tuning-and-false-positive-reduction`](../alert-tuning-and-false-positive-reduction/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Three stages, three verdicts:** emission, delivery and mapping fail independently. Collapsing them into "the logs are on" is the root cause of most false-negative claims in this leaf.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; read-only pipeline inspection and a test pipeline are safe, editing a production parser is a change-controlled action.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/L5/ctf_search (2), CYBER_CPT/github_security_md (2), OffsecCyber (1), Forensic_Toolkit_Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 1 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
