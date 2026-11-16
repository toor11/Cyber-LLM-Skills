---
name: mitre-attack-mapping
description: "Maps activity and coverage to MITRE ATT&CK: technique identification, sub-technique selection, and using ATT&CK for coverage assessment. Use when reporting detections or planning coverage."
family: detection-and-monitoring
tier: core
triggers: ["mitre attack", "attack mapping", "attack coverage", "technique mapping"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Mitre Attack Mapping - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

ATT&CK mapping is a join between observed behaviour and a versioned catalogue, and every stage of that join can go wrong silently. From v18 the catalogue no longer publishes per-technique detection content: a technique carries Detection Strategies, each with one or more Analytics, and those Analytics name the Data Components they consume — so a coverage claim is only meaningful if you can name the strategy and the data component behind it. v19 then relabelled the taxonomy underneath older documentation: `T1562` and its sub-techniques merged into `T1685 Disable or Modify Tools`, and Defense Evasion split into Stealth (still `TA0005`) and Defense Impairment (`TA0112`), so a layer built on a pre-v19 export renders those mappings to the wrong tactic. Mapping requires a pinned ATT&CK version, the actual event or alert you are describing (not the tool that produced the alert), and a stated granularity — technique versus sub-technique — because `T1059` and `T1059.001` are different claims with different evidence.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the ATT&CK version behind the mapping is unstated **THEN** pin it before continuing; a v18 layer and a v19 layer are not comparable, and `T1562` no longer exists as a technique in v19.
2. **IF** the observation is a tool name, a hash or an alert title **THEN** re-derive the mapping from the behaviour the event evidences; tool names map to software entries, not to techniques.
3. **IF** the evidence supports only the parent behaviour **THEN** map to the parent technique and say so; **IF** it distinguishes the specific mechanism **THEN** map the sub-technique. Never claim a sub-technique the telemetry cannot separate.
4. **IF** the output feeds a coverage percentage **THEN** name the denominator (techniques relevant to this environment, not the full 222) and the proof tier — library, deployed, collected or validated — because a tagged rule is not a validated detection.
5. **IF** the layer will be consumed by ATT&CK Navigator **THEN** emit layer JSON at schema version 4.5 and keep technique IDs as strings, including leading zeros in sub-technique IDs.
6. **IF** the mapping rests on a data source that is not collected, or is collected but failing its contract **THEN** downgrade the row to `Inconclusive (Telemetry Gap)` — NEVER record it as covered.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need mapping probes and coverage arithmetic | [`QUERIES.md`](QUERIES.md) | Rule-to-technique joins and unmapped-rule detection |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Navigator layer generation, DeTT&CT scoring, STIX queries |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | What to do when an incident has no mapping or no coverage |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Rule must carry the mapping itself | [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) | `tags: attack.tXXXX` is the machine-readable carrier |

## Procedure

1. **Confirm the evidence source and the catalogue version.** Fix the ATT&CK release you are mapping against, then enumerate what the alert or event actually contains — the process, the API call, the identity action. A mapping built on an alert title inherits whatever the vendor meant, which is rarely the technique definition.
2. **Choose granularity and tactic from the definition, not from intuition.** Read the technique's own description and its Detection Strategy analytics. If the analytics require a data component you do not collect, the mapping is aspirational; record it as a gap rather than as coverage.
3. **Define the baseline-versus-probe differential in mapping terms.** For a behaviour claim, compare the mapped technique's event rate per host or principal between a quiet window and the probe window. For a coverage claim, compare the set of techniques with a *validated* rule against the set with a *tagged* rule — the difference between those two sets is the honest gap.
4. **Name the stop condition.** Stop when the technique definition does not match the observed mechanism, when the catalogue version cannot be established, when the mapped sub-technique cannot be separated by available telemetry, or when the required data component is uncollected. Report `Inconclusive` with the specific reason rather than choosing the nearest-sounding technique.
5. **State what counts as proof.** Proof for a single mapping is a quoted clause of the technique description matched to a specific field in the event you hold. Proof for a coverage row is a rule that fired on a real or emulated instance of that technique with its required data component passing its contract gates.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Sigma `tags: attack.tXXXX` versus the alert's actual process lineage | rule-to-behaviour join | Whether the tag matches the evidenced mechanism or was inherited from a template |
| Technique IDs present in rules but absent from the environment's relevant set | denominator check | Coverage inflated by mapping to techniques the environment cannot expose |
| Rule count per tactic against the v19 tactic list including `TA0112` | tactic coverage | Whether pre-v19 rules still land under Defense Evasion after the split |
| Alert firing with its required data component null in the same window | strategy-to-data join | A mapping that exists on paper while its Data Component is not collected |
| Technique rows with no Detection Strategy analytics satisfied | strategy coverage | Nominal coverage: the technique is tagged but no analytic is implementable |
| Emulation result per technique with time-to-first-alert | validation tier | Which rows move from `deployed` to `validated`, and at what detection latency |
| Sub-technique claims where two sub-techniques share one observable | granularity conflict | The telemetry cannot distinguish `T1059.001` from `T1059.003`, so the parent is the only defensible claim |

## Worked Contrast

**Weak / Noisy Mapping Practice:**

```text
Weak claim: "Encoded PowerShell alert covers T1059.001 and T1027 and T1140."
Why it fails: one 4104 ScriptBlock event with a -enc argument evidences command
execution through PowerShell. It does not evidence obfuscation as a distinct
behaviour, and it does not evidence deobfuscation. Three IDs, one observation,
no defence of any of them — and the coverage number moves by three.
```

**High-Signal Grounded Mapping:**

```yaml
# One observation, one claim, with the evidence clause attached.
- technique: T1059.001
  name: Command and Scripting Interpreter - PowerShell
  attack_version: v19
  tactic: TA0002
  granularity: sub-technique
  evidence:
    source: WinEventLog:PowerShell
    event_id: 4104
    fields_observed: [ScriptBlockText, ScriptBlockId]
    clause: "execution of PowerShell commands and scripts"
  data_component: "Command Execution (DC0032)"
  detection_strategy: DET-powershell-scriptblock
  proof_tier: validated
  emulation: atomic T1059.001-1
  time_to_first_alert_seconds: 42
  not_claimed:
    - T1027    # no obfuscation evidence in this event
    - T1140    # no deobfuscation step observed
```

**Why this matters:** the strong form ties one technique and one granularity to a named field in a named event, records which data component and strategy support it, and explicitly lists what the same alert does *not* justify — which is what stops a single detection from being counted three times in a coverage figure.

## When It Is NOT This Issue

- **Tool-name mapping:** an alert titled after Mimikatz or Cobalt Strike is an observation about software, and ATT&CK models software separately from technique. Mapping the tool name to `T1003` asserts a credential-access behaviour the alert may not have observed.
- **Behaviour that is the product's normal job:** `T1053` scheduled tasks fire for every patch management agent, and `T1543.003` service creation fires for every installer. The mapping is technically correct and operationally useless; record it with the tool as a benign owner rather than as a coverage gap.
- **Pre-v19 tactic drift:** rules authored before the Defense Evasion split still carry `attack.defense_evasion` for behaviours that now sit in Defense Impairment (`TA0112`). The mapping is stale, not wrong-when-written.
- **Technique IDs reused across the split:** `T1562.001` now resolves to `T1685` and its sub-techniques. A layer referencing the old ID renders nothing in a v19 Navigator rather than rendering in the wrong place — silent disappearance, not a visible error.
- **Coverage percentage without a denominator:** "82% of ATT&CK covered" against all 222 techniques says nothing about whether the techniques relevant to this estate are visible. The number is only defensible against a named, environment-specific technique set.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER invent technique IDs, sub-technique numbers, Detection Strategy IDs or Data Component IDs** — if the ID is not in the pinned ATT&CK release you are working from, say the mapping is unresolvable.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `ATT&CK` was disabled, rotated out, or uncollected.**
- **NEVER present a coverage percentage without its denominator, its ATT&CK version and its proof tier.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the event, alert or emulation result behind each mapping was named with its fields, and the ATT&CK release version was pinned.
- [ ] **Granularity branch chosen:** parent technique versus sub-technique was decided from what the telemetry can separate, and recorded.
- [ ] **Differential defined:** tagged-versus-validated rule sets, or quiet-versus-probe technique rates, were compared rather than counted once.
- [ ] **Stop condition stated:** unresolved definition match, uncollected data component or indistinguishable sub-technique was named where it applied.
- [ ] **Proof standard met:** each claim carries an evidence clause and, for coverage rows, a fired rule plus a passing data component.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: mitre-attack-mapping
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
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **One observation, one claim:** the most common inflation is a single alert tagged with three techniques. Force the tag set to be defended field by field.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; emulation used to validate a mapping must be authorised and scoped in advance.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 37 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/mitre_attack_enterprise (12), CYBER_CPT/atomic_red_team (11), cyber-security/CyberSec-Dataset (8), ctf-solver-dataset (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 11 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
