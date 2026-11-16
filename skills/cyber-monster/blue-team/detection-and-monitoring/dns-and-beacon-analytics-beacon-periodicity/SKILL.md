---
name: dns-and-beacon-analytics-beacon-periodicity
description: Beacon periodicity and jitter analysis. Covers detecting repetitive callback patterns through interval analysis, jitter measurement and statistical baselining. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: detection-and-monitoring
tier: leaf
triggers: ["beacon analysis", "periodicity detection", "jitter detection"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [dns-and-beacon-analytics, dns-and-beacon-analytics-dga-and-tunneling, detection-engineering, sigma-rule-authoring]
parent: dns-and-beacon-analytics
---

# DNS and Beacon Analytics Beacon Periodicity - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md)

## Mechanism and Preconditions

A beacon is a sequence of check-ins with two properties worth measuring: the intervals between them cluster around a sleep value, and the payload sizes cluster around a template. Both properties are statistical, and both are attacked by the implant author: *jitter* randomises the interval by a percentage of the sleep, and *data jitter* pads the payload so size variance carries no signal. The robust way to score them is with order statistics rather than moments — a median interval plus a median absolute deviation (MAD) is unmoved by one missed check-in or one retransmit, while a mean and standard deviation shift under both. RITA-style scoring formalises this: Bowley skewness of the interval distribution (quartile-based, so outliers do not dominate), a dispersion score derived from the MAD, and a connection-count rate. The critical limitation to carry into any finding is scale: a dispersion score normalised against 30 seconds goes to zero for a ten-minute beacon with twenty percent jitter, so the score silently misses the careful implant and reliably catches the careless one. Periodicity therefore has to be evaluated at the *right resolution* for the suspected sleep value — a coarse bin collapses distinct periods, a fine bin smears a jittered one across neighbours — and the finding must state which resolution and which sleep band it covers.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `dns-and-beacon-analytics-beacon-periodicity` **THEN** start at parent class [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md) first.
2. **IF** the suspected sleep is under five minutes **THEN** use fine binning and a MAD normalised to that scale; **IF** the suspected sleep is ten minutes or longer **THEN** a 30-second dispersion normalisation will score zero, so switch to a per-series median-and-MAD comparison against peer series instead of an absolute scale.
3. **IF** the destination is contacted by many hosts with similar cadence **THEN** it is likely a legitimate service or agent heartbeat; **IF** the cadence and destination are unique to one host **THEN** the series is a candidate and the endpoint plane decides whether to escalate.
4. **IF** the channel is DNS **THEN** the interval evidence must come from endpoint DNS events or a span capture, because a caching resolver flattens the host's true cadence; **IF** the channel is TCP **THEN** connection records give both interval and byte series, and both should be scored.
5. **IF** payload sizes vary within a few percent across check-ins **THEN** size regularity adds strong evidence; **IF** sizes are padded and flat-random **THEN** say that size evidence is unavailable and rely on intervals plus destination rarity.
6. **IF** a series has fewer than ten observations **THEN** do not score it; a short series produces a high score from noise and cannot be distinguished from a burst.
7. **IF** telemetry source covering `interval` or `jitter` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md) | Plane coverage and per-host baselining before interval work |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Interval series extraction, resolution sweep, peer comparison |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Connection-record extraction, MAD computation, capture timing |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The names themselves look algorithmic rather than the cadence | [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) | Label entropy and record-type statistics |
| The cadence is fine but the process attribution is missing | [`endpoint-detection-and-edr-operations`](../endpoint-detection-and-edr-operations/SKILL.md) | Process tree, image load, and sensor health |

## Procedure

1. **Build the series from connection records, not from summaries.** For each (source host, destination) pair, extract an ordered timestamp list with the bytes in each direction. Summaries lose the ordering, and ordering is the entire signal.
2. **Screen for a minimum observation count and duration.** Require at least ten check-ins spread over at least ten expected sleep periods. A series shorter than that cannot distinguish a beacon from a burst of user activity.
3. **Choose the resolution from the suspected sleep band, and sweep it.** Score the same series at several bin widths and record the strength at each. A period that only appears at one cherry-picked resolution is not a period; one that appears consistently across neighbouring resolutions is.
4. **Score dispersion with order statistics.** Compute the median interval, the MAD, and Bowley skewness; derive a dispersion score relative to the series' own median rather than against a fixed 30-second constant, then note the sleep band where that normalisation is valid.
5. **Score size regularity as a separate, independent axis.** Compute the same statistics over the byte series. Report interval and size scores separately so a padded beacon shows a strong interval score and a weak size score, which is itself informative.
6. **Compare against peer series before escalating.** Look for other hosts contacting the same destination with similar cadence and similar size regularity. A peer group usually means a service; a single-host series against a rare destination is the candidate.
7. **Name the stop condition.** Stop and declare `Inconclusive` when the series is shorter than ten observations, when the resolution sweep shows the period only at one arbitrary bin width, when the sleep band exceeds the dispersion normalisation's valid range, when a caching resolver flattened the cadence, or when the only plane available is a summary that lost ordering.
8. **State what counts as proof.** Proof is one series with at least ten intervals, a period that survives a resolution sweep, a dispersion figure reported with its normalisation and sleep band, a size-series figure reported separately, a single-host destination rarity finding, and an issuing process from the endpoint plane. A high score from a single resolution is a lead, not a beacon.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Ordered interval series per (host, destination) with bytes in each direction | series extraction | The raw material for every cadence claim; summaries cannot substitute because ordering is the signal |
| Score stability across a resolution sweep of three or four bin widths | resolution sweep | Whether the period is real or an artefact of one bin width, which is the most common false positive in this technique |
| MAD of intervals relative to the series' own median | dispersion | How tightly check-ins cluster, robust to a single missed or duplicated connection |
| Bowley skewness of the interval distribution | symmetry | Whether the interval distribution is symmetric, the property jitter preserves and human activity rarely does |
| Byte-series regularity reported separately from intervals | size axis | Whether payload padding has been applied; a flat-random size series with a tight interval series is a padded implant |
| Count of other hosts contacting the same destination with a similar score | peer comparison | Whether the cadence belongs to a shared service, which changes the verdict without changing the score |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
ALERT when coefficient_of_variation(interval) < 0.1
# Mean and standard deviation over every connection a host makes.
# One retransmit or one missed check-in moves the mean, so the score
# collapses on real beacons and holds on short bursty series.
# No minimum observation count, so a five-connection burst scores highest.
# No resolution consideration, so a 10-minute jittered beacon is invisible.
```

**High-Signal Grounded Artifact:**

```text
For each (src_host, dst) series with n >= 10 over >= 10 expected periods:
  med   = median(intervals)
  mad   = median(|interval - med|)
  bowley = (Q1 + Q3 - 2*Q2) / (Q3 - Q1)        when Q3 - Q1 >= 10
  disp  = max(0, 1 - mad/med)                  normalised to the series' own median
  sweep = [disp @ 5s, disp @ 15s, disp @ 30s]  must hold across neighbours

ALERT when min(sweep) >= 0.8
      AND |bowley| <= 0.3
      AND n >= 10
      AND peers_contacting_dst <= 1
Report: src_host, dst, n, med, mad, disp at each resolution, byte-series MAD,
        issuing process from the endpoint plane, sleep band covered.
```

**Why this matters:** the strong form scores dispersion relative to the series' own median and requires the period to survive a resolution sweep, so it catches jittered long-sleep beacons that a fixed 30-second normalisation scores at zero; the weak form uses mean and standard deviation, which one retransmit destroys, and rewards short bursts precisely because it has no observation-count floor.

## When It Is NOT This Issue

- **Fixed-scale dispersion hiding long-sleep beacons:** a score normalised against 30 seconds returns zero for a ten-minute sleep with modest jitter, so the absence of a high score is not evidence of no beacon. Report the sleep band the scoring actually covers.
- **Caching resolver flattening the cadence:** the recursive resolver's upstream log sees one query per TTL rather than one per check-in, so a host's true period is longer than the log suggests. Cadence work belongs on endpoint or egress connection records.
- **Agent heartbeat with identical cadence:** endpoint agents, licensing checks, and monitoring probes check in on fixed intervals against a fixed destination, all from every host. Peer comparison is what separates them from a single-host beacon; without it the agent is the top finding every day.
- **Short series from a burst:** a software update that opens a dozen connections in two minutes has a near-zero dispersion over a tiny sample. The ten-observation and ten-period floor exists to exclude it, and removing the floor reintroduces the burst.
- **Retransmit and reconnect noise:** TCP retries inside one logical check-in add intervals that are not check-ins. De-duplicate connections into logical sessions before building the interval series, or the dispersion reflects transport behaviour.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host is not beaconing when the connection plane covering it was disabled, sampled, or flattened by a caching resolver.**
- **NEVER report a periodicity score without stating the resolution, the normalisation, the observation count, and the sleep band it covers.**
- **NEVER recommend destructive containment (isolating a host or blocking a destination fleet-wide) before confirming the destination's peer group and business function.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the connection or endpoint plane supplying ordered timestamps was identified, its sampling state confirmed, and caching or summarisation that would destroy ordering was ruled out.
- [ ] **Differential defined:** the series was scored at more than one resolution and compared against peer series contacting the same destination, not against a fleet constant.
- [ ] **Stop condition stated:** short series, single-resolution artefact, out-of-band sleep value, flattened cadence, or orderless summary is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** interval count, resolution sweep, dispersion with its normalisation and sleep band, separately reported size regularity, destination rarity, and endpoint process attribution.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: dns-and-beacon-analytics-beacon-periodicity
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Connection or endpoint plane, sampling state, series window in UTC, observation count, sleep band covered]
- **Behavioral Analysis**: [Median interval, MAD, Bowley skewness, dispersion across resolutions, byte-series regularity; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Peer hosts contacting the same destination, issuing process from the endpoint plane, payload capture if an active channel is authorized]
- **Containment / Detection / Hardening Action**: [Scoring rule with its resolution and sleep band, destination peer review before any block, sensor onboarding for missing planes]
```

## Related Sub-Skills

- [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md) - Detection and Monitoring (core)
- [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Robust statistics or nothing:** means and standard deviations are the reason periodicity detectors underperform. Order statistics survive the gaps that real networks produce.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); a beacon analytic maps to the application-layer C2 strategy for the platform that produced the connection record.
- **Safety & authorization:** Scoring is read-only over retained records; if an active channel must be characterised, coordinate with the incident owner and capture passively rather than interacting with the destination.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/nuclei_templates (1), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
