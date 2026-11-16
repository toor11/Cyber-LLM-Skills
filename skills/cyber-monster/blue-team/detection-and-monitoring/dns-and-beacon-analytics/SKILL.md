---
name: dns-and-beacon-analytics
description: "Detects command and control through DNS and beaconing: entropy analysis, beacon periodicity, DGA detection and tunnelling indicators. Use when hunting for covert channels."
family: detection-and-monitoring
tier: core
triggers: ["dns analytics", "beacon detection", "dga detection", "dns tunneling detection"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [dns-and-beacon-analytics-beacon-periodicity, dns-and-beacon-analytics-dga-and-tunneling, detection-engineering, sigma-rule-authoring]
---

# DNS and Beacon Analytics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md)

## Mechanism and Preconditions

A covert channel over DNS or HTTP leaves two independent traces: the *content* of individual messages (label entropy, query length, record type, response size) and the *cadence* of the conversation (inter-arrival intervals, byte-count stability, repetition against a small set of destinations). Neither is conclusive and both are cheaply obfuscated — an implant can pad payloads to flatten size variance and jitter its sleep to smear intervals, and a CDN object hash has entropy indistinguishable from a base64 chunk. What survives obfuscation is the *relationship between the three telemetry planes*: resolver or sensor logs know the name and the response code but not the process; the endpoint knows which image issued the query; the proxy or flow record knows the bytes and the destination. Detection therefore works best as a join keyed on source host and time, where the resolver supplies the name-level features, the endpoint supplies attribution, and the flow record supplies volume. The second structural point is baseline: DNS in a real estate is dominated by a handful of high-volume resolvers, telemetry agents, and CDN names, so a global entropy threshold catches the same five domains forever. The workable unit is per-host, per-registrable-domain deviation, measured against that host's own history.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `beacon-periodicity` **THEN** switch to [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) (1 hop).
2. **IF** the target specifically involves `dga-and-tunneling` **THEN** switch to [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) (1 hop).
3. **IF** the query evidence is resolver-side only **THEN** state that process attribution is unavailable and pivot to endpoint DNS telemetry; **IF** endpoint DNS events exist **THEN** use them as the primary plane, because they carry the process that made the query and are the only plane that can separate a browser from an implant.
4. **IF** the channel is suspected to be DNS **THEN** evaluate label entropy, label length, record type, and NXDOMAIN ratio per registrable domain; **IF** the channel is suspected to be HTTPS **THEN** DNS contributes only the destination name, and the cadence evidence must come from flow or proxy records instead.
5. **IF** the internal resolver forwards to an external resolver or the host uses DoH **THEN** resolver logs are incomplete by construction; say which hosts bypass and treat their absence as a visibility limit rather than as cleanliness.
6. **IF** the destination is a major CDN, cloud storage, or a sanctioned SaaS domain **THEN** a name-level anomaly is expected and low value; require the cadence or volume plane to corroborate before escalating.
7. **IF** telemetry source covering `entropy` or `periodicity` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md).
9. **IF** required preconditions for `dns-and-beacon-analytics` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `dns-and-beacon-analytics-beacon-periodicity` | [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `dns-and-beacon-analytics-dga-and-tunneling` | [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Per-host domain deviation, plane joins, resolver coverage |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Passive capture, Zeek log fields, RITA-style scoring |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The cadence question dominates and content features are secondary | [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) | Interval scoring, jitter, MAD-based dispersion |
| The name-level features dominate: entropy, record type, NXDOMAIN | [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) | Label statistics and tunnel-volume signals |

## Procedure

1. **Establish which DNS planes exist before scoring anything.** Enumerate resolver logs, endpoint DNS events (a Sysmon event 22 stream carries `QueryName`, `QueryStatus`, `QueryResults`, `Image`, and `ProcessGuid`), and any passive sensor at the egress. Note which hosts bypass the internal resolver through DoH or a local forwarder. A score computed over a plane that covers 60 percent of hosts describes those hosts only.
2. **Reduce names to registrable domains before aggregation.** Grouping on full query names splits one conversation across thousands of rows and hides the destination. Group on the registrable domain, then keep the label statistics as features of the parent.
3. **Compute per-host, per-domain features on a quiet baseline.** For each host and registrable domain, compute labels' mean length, entropy, unique-subdomain ratio, query count, NXDOMAIN ratio, and response-byte distribution over 7-14 quiet days. Store them; every later probe window is compared against this table rather than against a fleet constant.
4. **Branch on which plane can answer the question.** Content questions take the name-feature plane. Cadence questions take the timing plane from flow or connection records. Attribution questions require the endpoint plane. A conclusion that names a process without the endpoint plane is a guess.
5. **Join the planes on host and a bounded window, and report the join rate.** A finding where 90 percent of DNS rows fail to join an endpoint event is a visibility statement, not an attribution. The join rate belongs in the output.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the resolver covers part of the fleet, when a host's queries never appear on the endpoint plane (missing Sysmon event 22, or queries issued by a component outside the monitored API path), when the baseline window is shorter than seven days, or when the destination is a shared CDN whose name space makes entropy meaningless.
7. **State what counts as proof.** Proof of a covert channel is three planes agreeing: a name-level anomaly per host and domain, a cadence or volume deviation on the same host and domain in the same window, and a process on that host whose baseline never contacted the domain. Two planes is a lead, and the output must say which plane is missing.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Resolver coverage per host: query counts per day against the host inventory | coverage assertion | Which hosts' DNS activity the resolver can see, and therefore which hosts any later absence claim applies to |
| Endpoint DNS event with `Image` and `ProcessGuid` joined to the resolver name | plane join | Which process issued the query, the single most useful attribution field and one the resolver cannot supply |
| Per-host unique-subdomain ratio for one registrable domain | name-level feature | Whether the conversation uses a fresh name each time, the shape a tunnel or a chunked exfil produces |
| Inter-arrival median and dispersion per host and destination | cadence | Regularity of the conversation, independent of payload content and therefore resistant to padding |
| NXDOMAIN ratio per host and domain against that host's baseline | response-code profile | A domain-generation or query-only channel, where the authoritative side needs only to observe the query |
| Response-byte distribution per domain, split by record type | payload shape | Whether large answers are being carried in TXT or NULL records, which legitimate business traffic rarely uses at volume |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
ALERT when label_entropy > 3.8 OR query_length > 50
# One global threshold, evaluated per query name, with no host baseline.
# CDN object hashes, telemetry endpoints with GUID path segments, and
# antivirus lookups all exceed it continuously.
# The alert list fills with the same five domains every day, the rule is
# muted, and a real tunnel through a low-entropy scheme is never seen.
```

**High-Signal Grounded Artifact:**

```text
Per host, per registrable domain, trailing 14 days (quiet baseline):
  q_per_host      = count of queries
  uniq_ratio      = distinct subdomains / q_per_host
  p95_label_len   = 95th percentile of leftmost label length
  nxdomain_ratio  = NXDOMAIN responses / q_per_host
  interval_mad    = median absolute deviation of inter-arrival seconds

Probe window scored against the host's own baseline:
  ALERT when uniq_ratio > 0.9
        AND p95_label_len > baseline_p95 * 1.5
        AND interval_mad <= baseline_interval_mad
        AND domain NOT IN sanctioned_domains
Report: host, registrable_domain, uniq_ratio, p95_label_len, interval_mad,
        issuing process (endpoint plane), join_rate across planes.
```

**Why this matters:** the strong form compares each host to its own recent behaviour across three independent features and requires a process attribution from the endpoint plane, so the finding names a conversation rather than a string; the weak form applies a constant to individual query names, which every CDN and telemetry endpoint exceeds, and it cannot distinguish a tunnel from a hash.

## When It Is NOT This Issue

- **DoH or a local forwarder bypassing the resolver:** hosts configured for DNS-over-HTTPS or running a local stub that forwards elsewhere produce no resolver rows at all, so their absence is a visibility gap. Compare the resolver's host coverage against the endpoint inventory before drawing any conclusion.
- **CDN and telemetry name spaces:** object hashes, cache-busting parameters, and agent endpoint names with random path segments produce high entropy and high unique-subdomain ratios as a matter of design. Require cadence or volume corroboration, and exclude by registrable domain only after checking that the exclusion cannot cover an attacker who registers under the same parent.
- **Resolver caching flattening the cadence:** a caching resolver answers most repeats locally, so the upstream log sees a slower cadence than the host actually produced. Cadence analysis belongs on the endpoint or egress plane, not on the recursive resolver's upstream view.
- **NXDOMAIN from search-suffix resolution:** workstations append search suffixes and probe multiple candidates, generating NXDOMAIN bursts with no adversary involved. Measure NXDOMAIN per host and per registrable domain, not per query attempt.
- **Baseline window covering an outage:** a host that was offline for most of the baseline has a near-zero baseline, so any return to normal traffic scores as an anomaly. Require the baseline to contain the host's normal operating pattern before scoring.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host sent no covert traffic when the DNS plane covering it was bypassed, disabled, or uncollected.**
- **NEVER report a process attribution that did not come from an endpoint-plane event.**
- **NEVER recommend destructive containment (blocking a registrable domain fleet-wide, or isolating a resolver) before confirming blast radius, since a shared CDN domain may carry business traffic.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the DNS planes in scope were enumerated with their per-host coverage, and hosts bypassing the resolver were identified rather than assumed absent.
- [ ] **Differential defined:** per-host, per-domain features were compared against that host's own quiet baseline of at least seven days, not against a fleet-wide constant.
- [ ] **Stop condition stated:** partial resolver coverage, missing endpoint plane, short baseline, or a shared-CDN destination is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** name-level feature deviation, cadence or volume deviation, and a process whose baseline never contacted the domain are all reported, with the missing plane named when only two are available.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: dns-and-beacon-analytics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [DNS planes and per-host coverage, resolver bypass list, UTC baseline and probe windows, join rate to the endpoint plane]
- **Behavioral Analysis**: [Name features, cadence features, response-code profile; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Issuing process from the endpoint plane, flow or proxy volume for the same host and destination, sibling hosts contacting the same domain]
- **Containment / Detection / Hardening Action**: [Domain or host scoping decision with blast radius, resolver or sensor onboarding, rule to deploy with its baseline table]
```

## Related Sub-Skills

- [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) - Detection and Monitoring (leaf)
- [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Three planes or a caveat:** resolver, endpoint, and flow each answer a different question. Any answer that uses fewer must say which attribution or volume claim it cannot make.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); ATT&CK's application-layer C2 entries are the mapping target, and v18 detection strategies express them per platform.
- **Safety & authorization:** Analysis is read-only over retained logs and passive captures; never query an untrusted domain from a corporate resolver to "test" it, since that action itself signals interest to the operator.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (12), CYBER_CPT/pentest_partners (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
