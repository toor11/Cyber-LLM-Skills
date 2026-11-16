---
name: mitre-atlas-ml-threat-coverage
description: "Maps and assesses machine-learning systems against MITRE ATLAS tactics: ML supply-chain compromise, training/fine-tuning poisoning, membership inference, model inversion, and inference API extraction rate controls. Use when threat-modeling or auditing production ML pipelines."
family: ai-and-llm
tier: core
triggers: ["mitre atlas", "ml threat modeling", "membership inference", "model inversion", "ml pipeline security"]
cwe: [CWE-200]
owasp: [LLM04:2025]
attack: []
capec: []
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# Mitre Atlas ML Threat Coverage - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Mapping an AI system's assessment to MITRE ATLAS: each technique in the matrix describes an adversary action against an ML system (reconnaissance of model artefacts, resource development, initial access through a supply chain, model access, exfiltration, impact). The work is to map each finding and each control to the techniques it addresses, so coverage gaps are visible rather than implied.

- **A technique needs an observable.** Mapping a technique without naming the telemetry that would reveal it produces a coverage claim nobody can test.
- **Coverage is per technique, not per category.** A category marked green because one technique has a control hides the others inside it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a technique maps to no telemetry **THEN** record it as a gap rather than leaving it unmapped, because an absent row reads as not applicable.
2. **IF** a finding maps to several techniques **THEN** list them all, because the remediation for one may not address the others.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the system's components, the technique set in scope, and the telemetry sources available — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A coverage matrix with component, technique id, observable, and control per row, plus a gap list for techniques with no telemetry
- **First Check:** `python -c "import yaml; m=yaml.safe_load(open('atlas-map.yaml')); print(len(m['rows']))"`

1. Confirm the target surface: the system's components (data, training, model, serving, client) and which techniques in the matrix apply to each.
2. Choose the branch: component mapping when the goal is breadth, technique mapping when a specific behaviour is under test, and control mapping when validating existing detections.
3. Define the differential: for each mapped technique, the observable that would reveal it and the control that would stop it; a row with neither is a gap to report.
4. Name the stop condition: every in-scope technique has a row with an observable and a control, or an explicit gap entry.
5. Prove it: the matrix with component, technique, observable, and control per row, and a separate list of techniques with no telemetry.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Technique id with the component it applies to` | Makes the mapping specific; a technique without a component cannot be tested. |
| `Observable per technique` | The telemetry that would reveal the behaviour, which is what makes coverage measurable. |
| `Control per technique` | What would prevent or detect it; a technique with an observable but no control is a detection gap. |
| `Explicit gap list` | Keeps unmapped techniques visible instead of implicitly assuming they do not apply. |

## Worked Contrast

**Category-Level Coverage Claim:**

```text
Coverage: model access - covered (we have API logging).
Exfiltration - covered (we have DLP).
# BUG: no technique ids, no per-technique observable, no statement of which techniques the controls address
```

**Per-Technique Matrix With Observables and Gaps:**

```yaml
rows:
  - technique: model-artefact-recon
    component: model-hub
    observable: download events for private repositories
    control: access log review, private repo policy
  - technique: training-data-poisoning
    component: training-pipeline
    observable: provenance record per sample
    control: source allowlist and deduplication
gaps:
  - technique: inference-api-query-flooding
    reason: no per-account query telemetry retained beyond 24h
```

**Why this matters:** A category marked covered because a log exists says nothing about which techniques that log can reveal, and the gaps stay invisible. Listing technique ids with the component, the observable and the control produces a matrix where every row can be tested, and the explicit gap list records the techniques the telemetry cannot support rather than silently assuming they do not apply.

## When It Is NOT This Issue

- **Technique not applicable to the architecture.** A training-phase technique does not apply to an inference-only system; record the exclusion with the reason.
- **Control addressed by a platform provider.** Still a row, with the provider as the control owner; the gap is the absence of verification.
- **Observable retained for too short a period.** That is a real gap rather than a coverage claim; record the retention.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `mitre-atlas-ml-threat-coverage` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `mitre-atlas-ml-threat-coverage` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: mitre-atlas-ml-threat-coverage
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: LLM04:2025]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) - Blue Detection/Defense Counterpart
- [`llm-prompt-injection`](../llm-prompt-injection/SKILL.md) - AI and LLM (flagship)
- [`llm-jailbreak-and-guardrails`](../llm-jailbreak-and-guardrails/SKILL.md) - AI and LLM (core)
- [`rag-and-vector-store-attacks`](../rag-and-vector-store-attacks/SKILL.md) - AI and LLM (core)
- [`agentic-ai-and-mcp-security`](../agentic-ai-and-mcp-security/SKILL.md) - AI and LLM (core)
- [`model-and-artifact-supply-chain`](../model-and-artifact-supply-chain/SKILL.md) - AI and LLM (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `mitre-atlas-ml-threat-coverage` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
