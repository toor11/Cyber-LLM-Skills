---
name: detection-engineering
description: "Builds and maintains detections: identifying observable behaviours, writing and validating rules, mapping to ATT&CK, and managing the detection lifecycle including tuning and retirement. Use when creating, reviewing or improving detection coverage."
family: detection-and-monitoring
tier: flagship
triggers: ["detection engineering", "write detection", "detection rule", "detection lifecycle", "detection coverage"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering-behaviour-to-observable, detection-engineering-rule-lifecycle, sigma-rule-authoring, yara-rule-authoring]
---

# Detection Engineering - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **flagship** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A detection is a claim of the form "if the adversary does X, then sensor S will emit artifact A with field values F, and a query over A will select it". Every clause is separately falsifiable, and coverage fails at exactly one of them: the adversary may do X differently (behaviour drift), the sensor may not see it (visibility), the artifact may not carry the field (schema), or the query may not select it (logic). Detection engineering is the discipline of keeping those four clauses explicit and testing each one, which is why a rule without a stated sensor, artifact, and field set is unfalsifiable and cannot be reviewed. Coverage accounting has a second structural problem: one analytic may satisfy several techniques and one technique may need several analytics with no single rule being "the detection". ATT&CK v18 replaced per-technique detection lists with detection strategies and analytics, which matches this reality — a strategy names the behaviour and its analytics name the observable per platform. That makes the reviewable unit an analytic, not a rule, and it makes coverage claims honest only when they state the platform, the sensor, and the depth of variation the analytic actually covers.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `behaviour-to-observable` **THEN** switch to [`detection-engineering-behaviour-to-observable`](../detection-engineering-behaviour-to-observable/SKILL.md) (1 hop).
2. **IF** the target specifically involves `rule-lifecycle` **THEN** switch to [`detection-engineering-rule-lifecycle`](../detection-engineering-rule-lifecycle/SKILL.md) (1 hop).
3. **IF** the behaviour has no sensor that emits it **THEN** the deliverable is a visibility request with a named data source and field set, not a rule; **IF** the sensor exists but the field is unmapped **THEN** the deliverable is a parser or pipeline change — both are stated as gaps rather than shipped as detections.
4. **IF** the candidate analytic can be authored as a single-event match **THEN** do that first and measure precision; **IF** the behaviour is only visible as an ordering or a rate across events **THEN** author a correlation with an explicit `timespan` and `group-by`, and test the window boundary.
5. **IF** the work is authoring new logic **THEN** take the observable branch; **IF** the work is deciding whether an existing rule should be tuned, kept, or retired **THEN** take the lifecycle branch. A single change must not be both.
6. **IF** multiple backends must run the same detection **THEN** keep one source and compile per backend, and record the compiled diff; **IF** only one backend exists **THEN** author natively and skip the conversion layer rather than adding a build step that produces one artefact.
7. **IF** telemetry source covering the analytic's artifact is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).
9. **IF** required preconditions for `detection-engineering` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `detection-engineering-behaviour-to-observable` | [`detection-engineering-behaviour-to-observable`](../detection-engineering-behaviour-to-observable/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `detection-engineering-rule-lifecycle` | [`detection-engineering-rule-lifecycle`](../detection-engineering-rule-lifecycle/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Observable inventory, precision sampling, coverage and staleness audit |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Lint, compile, replay, and deploy entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Rules must be tested automatically before promotion | [`detection-as-code-and-testing`](../detection-as-code-and-testing/SKILL.md) | Fixtures, compilation artefacts, drift checks |
| An analytic must be proven against real behaviour | [`atomic-red-team-validation`](../atomic-red-team-validation/SKILL.md) | Emulation and telemetry-presence proof |

## Procedure

1. **Write the claim before the query.** State the behaviour in adversary terms, the sensor that can emit it, the artifact and fields that carry it, and the condition that distinguishes it from the benign version of the same action. A claim missing any one clause is a hypothesis, not an authorable detection.
2. **Verify visibility for that exact artifact.** Confirm the sensor emits the event on this build and platform (a Sysmon schema that includes the event ID, an EDR agent version that records the field, a cloud trail selector that covers the resource). Record what you confirmed and where.
3. **Enumerate the benign population the same artifact covers.** Administrative tools, deployment automation, backup agents, and monitoring probes produce the same artifact thousands of times a day. The analytic's discriminating condition must separate them by an entity or a rate, not by a keyword.
4. **Author the minimal selecting condition, then add exclusions by entity.** Prefer a single high-entropy fact (a parent-process pair, an unusual access right, a first-seen destination) over a concatenation of weak ones. Add each exclusion as a named, reviewable predicate rather than an inline `NOT`.
5. **Test the differential on three axes.** A positive fixture or atomic run must fire it, a near-miss negative fixture must not, and a historical sample must show a hit rate the queue can absorb. Failing the negative axis or the sample axis blocks promotion just as a failing positive does.
6. **Record the mapping at the analytic level.** Name the ATT&CK detection strategy and analytic the rule satisfies, the platforms it covers, and the variations it does not. Coverage depth is `none`, `partial`, or `broad`, and stating it prevents a technique-level percentage from overstating the programme.
7. **Name the stop condition.** Stop and declare `Inconclusive` when the sensor does not emit the artifact on any platform in scope, when the decisive field is unmapped for the sourcetype, when the negative population cannot be enumerated so precision is unknowable, or when the retention is shorter than the historical sample the claim needs.
8. **State what counts as proof.** Proof of a detection is a fired positive under controlled or observed conditions, a non-fired negative on the same field set, a sampled false-positive share the queue tolerates, and a recorded strategy/analytic mapping. A rule that fires is a candidate; the four together are a detection.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Sensor inventory for the artifact on each platform: event ID, provider, agent version, field list | visibility assertion | That the artifact exists where the rule runs; the first clause of the claim and the one most often assumed |
| Positive and negative fixture replay results side by side | discrimination test | That the logic separates the behaviour from its near-miss, which a hit count on production cannot show |
| Sampled alerts from the deployed rule, hand-labelled over a week | precision estimate | The false-positive share the queue will actually absorb, and the rationales that suggest the next exclusion |
| First-seen entity frequency for the excluded field per day | exclusion cost | How much traffic an exclusion suppresses, and whether it is narrowing toward the malicious case |
| Analytic-to-strategy mapping table with platform and depth columns | coverage depth | Whether the technique is covered narrowly, partially, or not at all, rather than counted once and forgotten |
| Rules with no disposition in the review window | staleness | Analytics nobody works, which are either broken or redundant and cannot be evaluated |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```yaml
title: Suspicious PowerShell
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
# Names no behaviour, so it cannot be falsified.
# Every management tool on the estate matches; the queue fills within an hour;
# the rule is disabled in week two and the technique is left with no coverage at all.
```

**High-Signal Grounded Artifact:**

```yaml
title: Encoded Command Execution From Office Parent
id: 8f2a1c40-3f7b-4a2d-9d61-0a1c5e9b7a11
status: test
description: Office application spawns PowerShell with an encoded command argument.
references:
  - ATT&CK detection strategy for script interpreter abuse (analytic: Office parent, encoded flag)
logsource:
  category: process_creation
  product: windows
detection:
  parent_office:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
  encoded_flag:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e JAB'
  condition: parent_office and encoded_flag
falsepositives:
  - Document-generation macros signed by the finance reporting tool (exclude by signer, not by hostname)
level: high
```

**Why this matters:** the strong rule names a behaviour, a sensor, an artifact and a discriminating field pair, so it can be falsified by a negative fixture and mapped to a specific analytic; the weak rule names an executable and nothing else, matches the entire management estate, and ends up disabled — which converts a noisy rule into zero coverage rather than into a detection.

## When It Is NOT This Issue

- **Sensor version that predates the event ID:** a rule reading a Sysmon event ID that the deployed schema does not config-filter produces a permanent zero. Check the schema version and the config's include rules before concluding the behaviour is absent.
- **Parser or pipeline change re-mapping the field:** a pipeline update that renames or drops a field turns a working rule into a silent no-op. Compare the compiled query's field names against the index's current mapping.
- **Backend conversion difference:** the same source compiled for two backends can produce different modifier behaviour, so a rule verified on one is unverified on the other. Diff the compiled outputs, not the sources.
- **Coverage percentage inflated by a single broad rule:** one analytic with `Image|endswith` on a common binary can be mapped to several techniques while detecting none of them meaningfully. Depth rating exists to expose exactly this.
- **Queue-driven tuning that trades away the behaviour:** an exclusion added to clear noise can remove the very field pair that made the rule specific. Re-fire the positive before accepting the exclusion.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean', or a technique 'covered', when telemetry covering the analytic's artifact was disabled, rotated out, or unmapped.**
- **NEVER report a rule as a detection without a positive result, a negative result, and a sampled precision figure.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the sensor, artifact, event identifier, and field list were verified on the deployed version and platform, and the verification is cited rather than assumed.
- [ ] **Differential defined:** positive and negative fixtures were both evaluated, and a historical sample was measured for the hit rate the queue must absorb.
- [ ] **Stop condition stated:** missing artifact on every platform in scope, unmapped decisive field, unenumerable benign population, or insufficient retention is named as the reason for `Inconclusive`.
- [ ] **Proof standard met:** fired positive, non-fired negative, sampled false-positive share, and a strategy/analytic mapping with platform and depth are all reported.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: detection-engineering
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Sensor and event identifier, platform and build, fields used, backends compiled, fixture set, sample window]
- **Behavioral Analysis**: [Behaviour claim, discriminating condition, benign population enumerated; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Second sensor or platform where the artifact differs; compiled-query diff per backend; atomic result if run]
- **Containment / Detection / Hardening Action**: [Rule text or pipeline fix to ship, exclusion to add with its cost, visibility request with owner and date]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering-behaviour-to-observable`](../detection-engineering-behaviour-to-observable/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering-rule-lifecycle`](../detection-engineering-rule-lifecycle/SKILL.md) - Detection and Monitoring (leaf)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **The claim is the artefact:** a review of a detection without the four clauses cannot find the defect. Reject authoring that begins with a query.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); report ATT&CK coverage against detection strategies and analytics with a depth rating, since a bare technique count invites false confidence.
- **Safety & authorization:** Authoring and testing are non-destructive; validate against fixtures, historical samples, and authorized emulation only, and never against production control planes or live customer data.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (8), CYBER_CPT/elastic_security (3), OffsecCyber (1), bug-bounty-pentest-en (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
