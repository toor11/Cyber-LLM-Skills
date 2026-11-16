---
name: ml-adversarial-and-data-poisoning
description: "Attacks ML systems at the model level: adversarial examples, training data poisoning, backdoors and model extraction. Use when the target trains or serves a model rather than merely prompting one."
family: ai-and-llm
tier: leaf
triggers: ["adversarial example", "data poisoning", "model backdoor", "model extraction"]
cwe: [CWE-1426]
owasp: [LLM04:2025]
attack: []
capec: [CAPEC-442]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# ML Adversarial and Data Poisoning - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Adversarial and poisoning work targets the model's learned behaviour rather than its input handling: a perturbation crafted to change a prediction, or training data modified so the model learns an association the attacker chooses. The audit question is what an attacker needs — query access, training-data write access, or both — and whether the resulting behaviour is detectable from outputs alone.

- **Perturbation needs query access and a target.** A model exposed only through a coarse API with rate limits is harder to attack than one that returns full probability vectors.
- **Poisoning needs a write path.** The finding is who can add or relabel training examples, and whether a small fraction of poisoned data can shift the behaviour for a chosen trigger.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the endpoint returns probability distributions or gradients **THEN** the perturbation attack surface is larger than a label-only API and the finding is the disclosure.
2. **IF** training data includes user-supplied content **THEN** the ingestion path is the poisoning surface; check deduplication and provenance before anything else.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the model's query interface, the training-data ingestion path, and the observable output surface — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A versioned evaluation set with clean and perturbed inputs, plus a data-provenance record for every training source
- **First Check:** `python -c "import json; print(len(json.load(open('eval-set.json'))['cases']))"`

1. Confirm the target surface: the query interface and what it returns, the training-data sources and who can write to them, and the outputs a user sees.
2. Choose the branch: perturbation review when query access exists, poisoning review when a write path exists, and backdoor review when a trigger could survive training.
3. Define the differential: compare the model's output on the clean input and the perturbed input, and require the change to be specific to the perturbation rather than general degradation.
4. Name the stop condition: a bounded number of queries per input and a fixed evaluation set, so the result measures the model rather than the query budget.
5. Prove it: the clean and perturbed inputs, both outputs, and the perturbation magnitude, so the change is attributable and reproducible.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Full probability vector in the response` | Enables gradient-free perturbation search; a label-only response raises the cost substantially. |
| `Training-data write path` | The poisoning surface; without one, only inference-time attacks apply. |
| `Trigger-specific behaviour change` | The backdoor signature: an output shift for inputs containing the trigger and no shift otherwise. |
| `Evaluation set with paired clean inputs` | Makes the differential measurable across model versions. |

## Worked Contrast

**Unbounded Query Probing With No Paired Baseline:**

```python
for eps in (0.01, 0.05, 0.1):
    out = model.predict(perturb(x, eps))
    print(eps, out)  # BUG: no clean baseline, unlimited queries, no evaluation set
```

**Paired Perturbation on a Fixed Evaluation Set:**

```python
EVAL = load_eval("eval-set.json")
results = []
for case in EVAL:
    clean = model.predict(case.input)
    perturbed = model.predict(perturb(case.input, eps=0.03))
    results.append({"id": case.id, "clean": clean.label, "perturbed": perturbed.label,
                    "margin": perturbed.confidence - clean.confidence})
shifted = sum(1 for r in results if r["clean"] != r["perturbed"])
print(shifted, "of", len(results))
```

**Why this matters:** Calling the model with a perturbed input and printing the label says nothing, because there is no clean reference and the query budget is unbounded. Evaluating a fixed set with paired clean and perturbed inputs produces a shift rate that can be compared across model versions, and the confidence margin shows whether the change is a marginal flip or a decisive one.

## When It Is NOT This Issue

- **Perturbation that changes only confidence.** A shift within noise without a label change is not a successful attack.
- **Label noise in training data.** Ordinary mislabelling is a data-quality issue; poisoning requires an adversarial intent and a trigger.
- **Model degradation after an upgrade.** A general accuracy drop is a regression, not a targeted attack.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ml-adversarial-and-data-poisoning` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ml-adversarial-and-data-poisoning` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ml-adversarial-and-data-poisoning
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1426 | Mapping: LLM04:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ml-adversarial-and-data-poisoning` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/llm_security (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
