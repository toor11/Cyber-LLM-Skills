---
name: cti-collection-and-enrichment
description: "Collects and enriches threat data: feed ingestion, deduplication, enrichment with context and confidence scoring. Use when building or maintaining intelligence pipelines."
family: threat-intelligence-and-hunting
tier: core
triggers: ["cti collection", "threat feed", "enrichment", "ioc enrichment"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, indicator-lifecycle-and-ioc-management, threat-hunting, hypothesis-driven-hunting]
---

# CTI Collection and Enrichment - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Collection and enrichment turn raw feeds into records a consumer can act on: deduplicated, timestamped, attributed to a source, and enriched with the context that makes an indicator meaningful (first seen, associated campaign, tooling, and whether it has been observed in your environment). The engineering problem is hygiene: without deduplication and provenance the store fills with the same indicator from six resellers, and without an observation join the consumer cannot tell a generic indicator from one that matters here.

- **CWE-345 framing:** an indicator is only as trustworthy as its provenance; an unauthenticated feed entry is an integrity risk in the pipeline.
- STIX 2.1 objects carry `created`, `modified`, and `confidence`, which is the minimum structure for deduplication and decay; flattening to bare values loses exactly those fields.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is what to do with the enriched indicator **THEN** open `indicator-lifecycle-and-ioc-management`.
2. **IF** the enrichment is about an actor or campaign **THEN** open `diamond-model-and-campaign-clustering`.
3. **IF** the feed is a commercial sensor feed with licensing constraints **THEN** check the sharing agreement before enriching with internal telemetry, since the enriched record may inherit restrictions.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Normalise to a structure before storing.** STIX 2.1 or an equivalent with `type`, `value`, `first_seen`, `last_seen`, `source`, `confidence`, and relationships. A bare value cannot be deduplicated or expired.
2. **Deduplicate on the observable plus its context, not the value alone.** The same IP from two feeds in two campaigns is two records with one observable; collapsing them destroys the campaign link.
3. **Choose the branch on the enrichment purpose.** Detection decisions take the observability branch (does it appear in our telemetry); hunting takes the context branch (what else does this actor use); blocking takes the false-positive branch (shared infrastructure risk).
4. **Define the baseline-vs-probe differential.** Baseline: a known-benign indicator from the same feed type. Probe: a known-malicious indicator with internal observations. The pipeline must rank them differently and show the observation count for each.
5. **State the stop condition and the proof.** Stop when every record carries provenance, first-seen, and an observation count; proof is one indicator's full lineage from feed to store to consumer query.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Same observable present from four feeds with different first-seen dates | Proves the store is preserving provenance; the earliest date is the useful one and the others are corroboration. |
| Indicator with no internal observation count | Proves enrichment stopped at the feed boundary, so the consumer cannot distinguish generic from relevant. |
| Feed entry lacking authentication or signature | Proves an integrity gap; anyone who can modify the feed can inject indicators. |
| Record whose confidence came from the feed's marketing label | Proves confidence is being copied rather than assessed, which corrupts every downstream ranking. |

## Worked Contrast

**Collection that flattens feeds into an undated value list:**

```text
feed_a.txt -> 203.0.113.44
feed_b.txt -> 203.0.113.44
feed_c.txt -> 203.0.113.44
blocklist.txt (appended, dedup on exact line, no dates)
count: 18,402 indicators
consumer: "use the blocklist"
```

**Enrichment that preserves provenance, dates, and an observation join:**

```json
{
  "type": "ipv4-addr",
  "value": "203.0.113.44",
  "sources": [
    {"name": "vendor-a", "first_seen": "2026-08-02", "confidence": 70, "campaign": "affiliate-X"},
    {"name": "vendor-b", "first_seen": "2026-09-11", "confidence": 55, "campaign": "affiliate-X"},
    {"name": "isac-feed", "first_seen": "2026-08-05", "confidence": 60}
  ],
  "observed_in_estate": {"hits": 3, "first": "2026-10-19", "sensor": "dns-proxy"},
  "infrastructure": {"asn": 64500, "hosting": "bulletproof", "shared_with_benign": true},
  "recommended_action": "hunt",
  "action_rationale": "shared hosting; blocking risks false positives, observation is unambiguous"
}
```

**Why this matters:** The first pipeline keeps the value and discards everything that made it usable, so the consumer cannot tell how old it is, who reported it, or whether it has ever been seen here. The second keeps per-source provenance with dates and confidence, records the internal observation with its sensor, and recommends hunt rather than block because the hosting is shared - which is the judgement the consumer needs.

## When It Is NOT This Issue

- **Indicator absent from your telemetry.** That is a coverage question, not a reason to discard the record; mark it unobserved and keep it for hunting.
- **Duplicate value across campaigns.** Keep both relationships; the shared observable is a clustering signal, not noise.
- **Feed confidence labels that disagree.** Disagreement is information; record both rather than averaging them into a number nobody can explain.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `feed ingest` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cti-collection-and-enrichment` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: cti-collection-and-enrichment
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`hypothesis-driven-hunting`](../hypothesis-driven-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`adversary-tracking-and-attribution`](../adversary-tracking-and-attribution/SKILL.md) - Threat Intelligence and Hunting (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cti-collection-and-enrichment` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 4 |
| Top sources | osint-tool-database (16), CYBER_CPT/nuclei_templates (2), CYBER_CPT/blackhills (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 16 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
