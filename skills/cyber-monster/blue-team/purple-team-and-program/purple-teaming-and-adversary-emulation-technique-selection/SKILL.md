---
name: purple-teaming-and-adversary-emulation-technique-selection
description: Purple team technique selection. Covers choosing techniques based on threat relevance, detection coverage gaps and safe execution constraints. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: purple-team-and-program
tier: leaf
triggers: ["purple technique selection", "emulation scope", "coverage gap selection"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, purple-teaming-and-adversary-emulation-execution-and-validation, remediation-tracking-and-verification, security-program-and-control-frameworks]
parent: purple-teaming-and-adversary-emulation
corpus_sparse: true
---

# Purple Teaming and Adversary Emulation Technique Selection - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **leaf** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Technique selection is a prioritisation problem with three inputs: threat relevance (what actors targeting you actually do), coverage gap (what your analytics do not detect), and safety constraint (what you can emulate without risking production). The best exercise is the intersection - a high-relevance technique with a known gap that can be emulated safely - and the worst is a high-relevance technique you already detect well, because it consumes the window and teaches nothing.

- **CWE-693 framing:** selection is about which protection mechanism to test, so the criterion is effectiveness evidence, not technique popularity.
- ATT&CK v19 (April 2026) split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112), and T1562 was restructured into T1685 Disable or Modify Tools, so technique ids in an older selection list need re-checking.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the technique list is chosen and you need to run it **THEN** open `purple-teaming-and-adversary-emulation-execution-and-validation`.
2. **IF** the relevance input is missing **THEN** get it from `threat-intelligence-and-cti-tactical-intelligence` rather than picking techniques by familiarity.
3. **IF** the constraint is regulatory **THEN** check the framework's requirements; TIBER-EU's January 2025 revision mandates purple teaming within a DORA-aligned TLPT.
4. **IF** the target narrows to `purple-teaming-and-adversary-emulation` **THEN** open [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Score threat relevance from your own intelligence, not from a generic top-ten.** Which techniques appear in reports about your sector, and which are used by actors who have targeted organisations like yours. Record the source per technique.
2. **Score coverage from the detection library.** For each candidate technique, does an analytic exist, is it enabled, and when was it last validated? A technique with a recent validation is low priority.
3. **Score safety from the emulation requirement.** Read-only behavioural emulation is safe anywhere; anything requiring persistence, credential access, or lateral movement needs an isolated segment or an approved window.
4. **Choose the branch on the score combination.** High relevance plus gap plus safe takes the immediate branch; high relevance plus no gap takes the regression-test branch (cheap re-validation); high relevance plus unsafe takes the tabletop branch until an isolated environment exists.
5. **State the stop condition and the proof.** Stop when the list has a rationale per technique and a safety classification; proof is the scoring sheet with sources, not the final list.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Technique selected because it appears in a sector report and has no analytic | Proves the selection is evidence-driven; both halves of the criterion are recorded. |
| Technique selected because it is popular in ATT&CK statistics | Proves selection by familiarity, which produces exercises that validate what is already known. |
| Technique with an existing analytic routed to regression testing | Proves the list distinguishes new coverage from maintenance. |
| Technique requiring privileged action deferred to a tabletop | Proves the safety constraint is respected rather than argued away. |

## Worked Contrast

**Selection by technique popularity:**

```text
Exercise plan Q4
Techniques: T1059.001, T1055, T1071.001, T1105, T1566.001
Rationale: these are the most common techniques in the MITRE top list
Coverage: unknown
Safety: not assessed
Environment: production
```

**Selection scored on relevance, coverage, and safety with sources:**

```text
Candidate techniques - PT-2026-08

T1218.011  rundll32 proxy execution
  relevance: high   - 2 sector reports (2026-08, 2026-10) name Office->rundll32 chains
  coverage : GAP    - no analytic; nearest (A-221) requires a specific parent list that excludes Excel
  safety   : safe   - read-only execution, no persistence, cleanup by process exit
  branch   : immediate

T1053.005  scheduled task creation
  relevance: high   - appears in both reports as the persistence step
  coverage : PARTIAL- analytic A-305 exists but filters short task names
  safety   : safe   - task created and deleted within the window
  branch   : regression + tuning

T1003.001  LSASS memory access
  relevance: high
  coverage : analytic exists, validated 2026-09
  safety   : UNSAFE in production (credential access on live hosts)
  branch   : tabletop until the isolated range is available (target Q1)

T1566.001  spearphishing attachment
  relevance: medium - our mail gateway blocks the known patterns
  coverage : gateway control, not an analytics question
  branch   : out of scope for this exercise
```

**Why this matters:** The first plan picks techniques by popularity, cannot say whether they are already covered, and would run a credential-access technique in production. The second records a source for relevance, a coverage verdict with the reason, a safety classification, and a branch - which is what makes the list defensible and the window productive.

## When It Is NOT This Issue

- **Technique with a recent validation.** Re-testing it consumes the window for no new information; route it to a regression suite instead.
- **Technique outside your platform.** macOS or cloud techniques on a Windows-only estate are irrelevant regardless of prevalence.
- **Technique whose emulation requires malware.** The safe emulation boundary excludes real malicious artefacts; use a behavioural proxy or a tabletop instead.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `threat relevance` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `purple-teaming-and-adversary-emulation-technique-selection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: purple-teaming-and-adversary-emulation-technique-selection
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) - Purple Team and Program (core)
- [`purple-teaming-and-adversary-emulation-execution-and-validation`](../purple-teaming-and-adversary-emulation-execution-and-validation/SKILL.md) - Purple Team and Program (leaf)
- [`remediation-tracking-and-verification`](../remediation-tracking-and-verification/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `purple-teaming-and-adversary-emulation-technique-selection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
