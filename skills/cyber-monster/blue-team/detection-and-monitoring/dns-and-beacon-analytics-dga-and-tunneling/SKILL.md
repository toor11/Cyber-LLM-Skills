---
name: dns-and-beacon-analytics-dga-and-tunneling
description: DGA and DNS tunnelling detection. Covers identifying algorithmically generated domains and DNS tunnelling through entropy, length and record-type anomalies. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: detection-and-monitoring
tier: leaf
triggers: ["dga detection", "dns tunnel detection", "entropy analysis"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [dns-and-beacon-analytics, dns-and-beacon-analytics-beacon-periodicity, detection-engineering, sigma-rule-authoring]
parent: dns-and-beacon-analytics
---

# DNS and Beacon Analytics Dga and Tunneling - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md)

## Mechanism and Preconditions

Two name-level phenomena are often conflated and behave differently. A domain-generation algorithm produces many *candidate* names, most of which do not exist, so its signature is a high proportion of NXDOMAIN responses for names that look machine-generated under one or a few parent domains. A DNS tunnel produces *successful* lookups of names whose leftmost labels carry encoded payload, so its signature is a high unique-subdomain ratio, long labels, an unusual record type (TXT, NULL, rarely-used types), and a response-size distribution that is larger and more uniform than ordinary A-record traffic. Feature-based scoring over label statistics catches both families in principle, but the discriminative power is weaker than it looks: a CDN object hash, a certificate-transparency lookup, a telemetry endpoint with a GUID path segment, and a base64-encoded tunnel chunk are statistically similar under entropy and length alone. What separates them is *the relationship between queries and answers* — tunnels exfiltrate or retrieve data, so the byte volume and the unique-name count per parent domain grow together in a way ordinary resolution does not, and the parent domain is young, thinly hosted, and rarely seen across the fleet. Multi-feature scoring with a per-host baseline plus parent-domain rarity outperforms any single entropy threshold, and the finding must state which features carried the decision.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `dns-and-beacon-analytics-dga-and-tunneling` **THEN** start at parent class [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md) first.
2. **IF** most queries under a parent domain return NXDOMAIN **THEN** evaluate it as a DGA hypothesis; **IF** most return NOERROR with large or uniform answers **THEN** evaluate it as a tunnel hypothesis. Applying tunnel thresholds to a DGA candidate wastes the analysis, and the reverse is also true.
3. **IF** the record type is TXT, NULL, or another rarely-used type **THEN** treat it as a feature that raises a score and never as proof on its own; **IF** the channel uses A or AAAA records exclusively **THEN** record-type evidence is absent and the unique-name and byte-volume axes must carry the finding.
4. **IF** the parent domain is contacted by one or two hosts **THEN** rarity supports escalation; **IF** it is contacted by most of the fleet **THEN** it is infrastructure and a name-level anomaly is expected.
5. **IF** the parent domain's registration age or hosting is unknown **THEN** obtain enrichment before escalating, and record which enrichment source was used; **IF** no enrichment is available **THEN** say so rather than inferring age from the name.
6. **IF** the resolver is caching and the query/byte correlation is the evidence **THEN** use endpoint DNS events plus egress flow records; the resolver's own view loses the per-query byte relationship.
7. **IF** telemetry source covering `entropy` or `NXDOMAIN ratio` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md) | Plane coverage and per-host baselining before name scoring |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Label statistics, NXDOMAIN share, query/byte correlation, rarity |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Capture extraction, entropy computation, record-type enumeration |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The interesting signal is the cadence of successful lookups | [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) | Interval and dispersion scoring |
| The name is fine but the process behind it is suspect | [`endpoint-detection-and-edr-operations`](../endpoint-detection-and-edr-operations/SKILL.md) | Process attribution and sensor health |

## Procedure

1. **Fix the hypothesis before choosing features.** A DGA candidate is evaluated on NXDOMAIN share and candidate-name volume; a tunnel candidate on unique-subdomain ratio, label length, record type, and query-to-byte correlation. Running all features against both hypotheses produces a score nobody can interpret.
2. **Aggregate to the registrable parent before computing anything.** Label statistics belong to the parent domain, not to individual query names; computing per-name entropy discards the repetition that makes a tunnel look like a tunnel.
3. **Compute the label feature set on the leftmost label only.** Length, digit ratio, entropy over the label's character distribution, and alphabet resemblance (base32, base64url, hex) belong to the leftmost label; the parent contributes a constant that dilutes each of them.
4. **Add the query-and-answer relationship.** For each parent domain, compute queries per host, distinct names per host, total answer bytes per host, and their ratio. A tunnel moves data, so names and bytes grow together; ordinary resolution grows names without growing bytes proportionally.
5. **Establish parent-domain rarity across the fleet.** Count hosts contacting the parent in the baseline window. Rarity is the feature that separates a tunnel endpoint from a CDN, and it is the one most often omitted from published thresholds.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the resolver covers part of the fleet, when endpoint DNS events are absent so the process cannot be attributed, when the parent is a shared CDN or public suffix whose name space is not attributable to one tenant, or when no enrichment exists for registration age and hosting.
7. **State what counts as proof.** Proof is a parent domain with a per-host unique-subdomain ratio far above that host's baseline, a label-statistics profile that is anomalous on at least two independent axes, a query-to-byte relationship consistent with data transfer, fleet-level rarity of the parent, and an issuing process from the endpoint plane whose baseline never resolved it. State which of the five are present.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| NXDOMAIN share per parent domain per host, against that host's own baseline | DGA hypothesis | Whether the host is generating candidate names that do not resolve, the DGA signature as distinct from a tunnel |
| Unique-subdomain ratio and leftmost-label length distribution per parent | tunnel hypothesis | Whether each lookup carries a fresh, large label, which is the shape of an encoded payload |
| Record-type mix per parent domain, with TXT and NULL counts | record-type profile | Unusual answer channels; a feature that raises a score and never proves a tunnel alone |
| Query count against answer bytes per parent and host | data-transfer correlation | Whether names and transferred bytes grow together, the property ordinary resolution does not have |
| Distinct hosts contacting the parent within the baseline window | fleet rarity | Whether the domain is infrastructure the estate depends on, or a single-host destination |
| Alphabet resemblance of the leftmost label to base32, base64url, or hex | encoding profile | Which encoding family a label belongs to, useful for characterising the channel after it is found |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
ALERT when entropy(leftmost_label) > 3.8
# A single feature, evaluated per query, with no parent aggregation.
# CDN hashes, certificate-transparency names and GUID telemetry paths
# all exceed it; base32 tunnel chunks are near it and sometimes under it.
# No NXDOMAIN share, no byte correlation, no rarity, no process.
# The list fills with the same infrastructure every day and is muted.
```

**High-Signal Grounded Artifact:**

```text
Per registrable parent domain, per host, trailing 14 days:
  uniq_ratio   = distinct qnames / queries
  p95_label    = 95th percentile leftmost-label length
  nx_share     = NXDOMAIN / queries
  bytes_per_q  = answer_bytes / queries
  hosts_seen   = distinct hosts contacting the parent

Tunnel candidate when:
  uniq_ratio >= 0.9  AND p95_label >= 40
  AND bytes_per_q >= host_baseline_p95 * 2
  AND hosts_seen <= 2
DGA candidate when:
  nx_share >= 0.5    AND uniq_ratio >= 0.8
  AND distinct candidate names per host >= 50
Both require: issuing process from the endpoint plane, and parent enrichment
(registration age, hosting ASN) recorded with its source.
```

**Why this matters:** the strong form separates the two hypotheses, aggregates at the parent, and adds the two features that survive obfuscation — byte-per-query growth and fleet rarity — so its output is a named domain with a data-transfer shape rather than a stream of high-entropy strings; the weak form applies one threshold to individual labels and therefore flags the CDN it will always flag.

## When It Is NOT This Issue

- **CDN and object-storage name spaces:** content hashes and cache-busting names produce maximal entropy under a legitimate parent that many hosts contact. Fleet rarity and byte-per-query behaviour separate them, and a per-name entropy threshold never will.
- **Certificate-transparency and security-vendor lookups:** agents that resolve hashed names or reputation endpoints generate large volumes of random-looking labels under a stable set of parents, from every host. They appear at the top of any per-name ranking and are the reason parent rarity is required.
- **Search-suffix and probe resolution:** clients append suffixes and probe candidate names, producing NXDOMAIN bursts that look like a DGA from one host. Aggregating at the parent collapses the probe candidates, and the burst usually stops within seconds.
- **Base32 and base64 in legitimate protocols:** DKIM selectors, ACME challenge names, and service-discovery records carry encoded labels by design. Record type and parent rarity decide, not label statistics.
- **Caching resolver distorting byte-per-query:** the resolver's answer size reflects the cached copy rather than the host's request pattern, so the correlation belongs on endpoint or egress records. Computing it on resolver logs produces a plausible but meaningless figure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host resolved no tunnelling domain when the DNS plane covering it was bypassed, disabled, or uncollected.**
- **NEVER report registration age, hosting provider, or domain reputation without naming the enrichment source that supplied it.**
- **NEVER recommend blocking a registrable domain fleet-wide before confirming its fleet rarity and business function, since a shared parent may carry production traffic.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the DNS plane with per-host coverage was enumerated, resolver bypasses identified, and the parent-domain aggregation key verified against the query data.
- [ ] **Differential defined:** each parent domain was compared against the contacting host's own baseline and against fleet-level rarity, on at least two independent feature axes.
- [ ] **Stop condition stated:** partial coverage, missing endpoint plane, shared-CDN parent, or absent enrichment is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** unique-subdomain ratio, label profile on two axes, query-to-byte relationship, fleet rarity, and issuing process are each reported as present or missing.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: dns-and-beacon-analytics-dga-and-tunneling
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [DNS planes and per-host coverage, baseline and probe windows in UTC, enrichment sources used, endpoint plane availability]
- **Behavioral Analysis**: [NXDOMAIN share, unique-subdomain ratio, label profile, record-type mix, query-to-byte relationship, fleet rarity; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Issuing process from the endpoint plane, egress byte volume for the same host and parent, registration and hosting enrichment with source]
- **Containment / Detection / Hardening Action**: [Scoped block or sinkhole proposal with blast radius, per-parent baseline table to deploy, resolver or endpoint onboarding gap]
```

## Related Sub-Skills

- [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md) - Detection and Monitoring (core)
- [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Two hypotheses, two feature sets:** DGA and tunnelling share a name space but not a signature. Declaring which hypothesis you are testing keeps the scoring interpretable.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); the parent skill owns the plane-coverage discussion and this leaf owns the name-level statistics.
- **Safety & authorization:** Read-only over retained logs and passive captures; never query a candidate domain to test it, and never register or interact with infrastructure controlled by the suspected operator.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 9 |
| Top sources | cyber-security/CyberSec-Dataset (2), CYBER_CPT/ctftime (2), cyber-security/attack-patterns-detection.json (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
