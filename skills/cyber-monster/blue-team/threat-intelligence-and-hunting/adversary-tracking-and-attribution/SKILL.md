---
name: adversary-tracking-and-attribution
description: "Tracks threat actors and assesses attribution: infrastructure clustering, tooling overlap, victimology and confidence language. Use when reporting on a campaign or actor."
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["adversary tracking", "attribution", "threat actor profiling", "campaign tracking"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
---

# Adversary Tracking and Attribution - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Attribution is a probabilistic judgement about who is responsible, built from infrastructure, tooling, victimology, and operational patterns, and it is only worth making when a decision depends on it. The honest product separates what was observed from what is inferred, states the alternative hypotheses it considered, and gives a confidence level with its basis. Naming an actor is the least useful output - the pattern that lets you predict their next move is the useful one.

- **CWE-200 framing:** attribution products frequently aggregate victim details; audience and classification belong with the judgement.
- Shared tooling is the weakest signal: commodity loaders and leaked builders produce clusters that look like one actor and are several.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is campaign clustering rather than naming **THEN** open `diamond-model-and-campaign-clustering`, which gives the vertex-and-pivot structure.
2. **IF** the consumer needs to act on the actor's techniques **THEN** open `threat-intelligence-and-cti-tactical-intelligence` and stop attributing.
3. **IF** the claim would be published externally **THEN** require a second independent source and legal review before it leaves the organisation.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **State the decision that depends on attribution.** A takedown request, a sector warning, a sanction determination, or a defensive priority. If no decision changes, the product is curiosity and should be labelled as such.
2. **Collect signals by vertex.** Infrastructure (domains, certificates, hosting), capability (malware family, builder, tooling), victimology (sector, geography, size), and operational pattern (timing, tradecraft, language artefacts).
3. **Choose the branch on signal strength.** Unique capability plus unique infrastructure takes the named-cluster branch; shared commodity tooling takes the unnamed-cluster branch; single-signal matches take the watchlist branch with no attribution claim.
4. **Define the baseline-vs-probe differential.** Baseline: how common each signal is in the wider ecosystem (a commodity loader used by twelve clusters). Probe: the same signal restricted to the observed set. A signal is only discriminating when its baseline prevalence is low.
5. **State the stop condition and the proof.** Stop when the product names alternative hypotheses, the signal that distinguishes them, and a confidence level with its basis; proof is the signal-prevalence comparison, not the actor name.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Unique builder plus unique certificate pattern across two incidents | Proves a cluster worth naming; both signals are low-prevalence, which is what makes the link discriminating. |
| Commodity loader shared by many clusters | Proves the link is not specific; attributing on a loader alone merges unrelated actors. |
| Victimology overlap only | Proves a hypothesis, not an attribution; sector targeting is broad and re-used by many groups. |
| Alternative hypothesis documented and rejected with evidence | Proves the analysis considered the obvious competing explanation, which is the minimum standard for a claim. |

## Worked Contrast

**Attribution by tooling overlap:**

```text
Incident 1 used Cobalt Strike beacon.
Incident 2 used Cobalt Strike beacon.
Conclusion: same actor, likely APT-X.
Confidence: high.
Action: attribute publicly.
```

**Attribution with prevalence, alternatives, and calibrated confidence:**

```text
Question: is incident 2 the same cluster as incident 1?  Decision: whether to warn the sector.

Signals
  capability   : beacon config (watermark 0x1a2b, sleep 47s, jitter 23%) - prevalence in our corpus: 1.2%
  infrastructure: /24 203.0.113.0/24 re-used; cert serial pattern 0x4f... (self-signed, 63-day life)
  operational  : both intrusions began 02:00-04:00 local, same victim sector, same initial access vector
  victimology  : mid-size logistics, same region

Competing hypotheses
  H1 same cluster                     - explains all four signals, two low-prevalence
  H2 shared builder, different actors  - explains capability, not the /24 re-use or the cert pattern
  H3 copycat using leaked config       - possible; would not explain the /24 re-use

Assessment (moderate confidence)
  H1 is most likely. The beacon watermark and the certificate pattern are both low-prevalence in
  our corpus, and the /24 re-use is independent of tooling. H3 cannot be excluded without
  infrastructure registration data we do not have.

What would change it
  Registration overlap with a known cluster, or a third incident with a different /24 and the same cert pattern.

Action: warn the sector with the observable pattern, no actor naming. Naming deferred until H3 is excluded.
```

**Why this matters:** The first record treats a ubiquitous tool as an identifier and reaches high confidence from one signal, which is how unrelated intrusions get merged. The second measures prevalence for each signal, states competing hypotheses and what each explains, names the signal that would change the judgement, and delivers the actionable pattern without the name.

## When It Is NOT This Issue

- **Shared C2 framework.** Cobalt Strike, Sliver, and Metasploit appear across dozens of clusters; the framework is not an identifier.
- **Same victim sector.** Sector targeting is the least specific signal and is routinely shared.
- **Confidence asserted without a prevalence estimate.** A signal whose base rate is unknown cannot support a claim.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `infrastructure cluster` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `adversary-tracking-and-attribution` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: adversary-tracking-and-attribution
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`hypothesis-driven-hunting`](../hypothesis-driven-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `adversary-tracking-and-attribution` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/gh_advisories (4), osint-ctf-corpus-fr (1), CYBER_CPT/osv (1), CYBER_CPT/wiz_research (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
