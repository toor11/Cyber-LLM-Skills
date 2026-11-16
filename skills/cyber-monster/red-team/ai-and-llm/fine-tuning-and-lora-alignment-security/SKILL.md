---
name: fine-tuning-and-lora-alignment-security
description: "Assesses security risks in custom fine-tuning, LoRA/QLoRA adapters, and RLHF datasets: safety-alignment degradation from small poisoned subsets, sleeper trigger phrases, and PII/secret memorization verification before weight release. Use when fine-tuning or auditing custom model weights."
family: ai-and-llm
tier: leaf
triggers: ["fine tuning security", "lora adapter backdoor", "alignment degradation", "canary memorization test"]
cwe: [CWE-506]
owasp: [LLM04:2025]
attack: []
capec: []
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# Fine Tuning and Lora Alignment Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Fine-tuning and adapter training change a model's behaviour with data the application may not control: a LoRA adapter is a small artefact that alters responses, and a fine-tuning dataset is a write path into the model's weights. The audit question is who can supply training data or an adapter, whether the result preserves the safety behaviour the base model had, and whether the artefact's provenance is verified.

- **An adapter is a behaviour patch.** A LoRA can suppress refusals or add a trigger response without touching the base weights, so adapter provenance is a security property.
- **Alignment must be re-tested after training.** A fine-tune can degrade refusal behaviour on classes unrelated to the training objective, and the evaluation must be run against the new artefact.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an adapter is loaded from an external source **THEN** treat it as untrusted code-adjacent data and verify its provenance and hash before loading.
2. **IF** user data enters the training set **THEN** check deduplication and a canary test, because a model that memorised a canary will produce it when prompted.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the training-data sources, the adapter provenance, and the safety evaluation run against the trained artefact — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A versioned safety evaluation set run against the base and the trained artefact, plus a provenance record and hash for every adapter and dataset
- **First Check:** `python -c "import json; print(len(json.load(open('safety-eval.json'))['cases']))"`

1. Confirm the target surface: the training-data sources and their write access, the fine-tuning procedure, and every adapter loaded at inference.
2. Choose the branch: data review when user content enters training, adapter review when third-party adapters are loaded, and evaluation review when a trained artefact replaces a base model.
3. Define the differential: run the same safety evaluation set against the base model and the trained artefact; the differential is a behaviour class that changed.
4. Name the stop condition: the evaluation set shows no regression outside the intended objective, or the regression is documented with its trigger.
5. Prove it: both evaluation results, the artefact hashes, and the changed cases, so the regression is attributable to the training step.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Safety evaluation on base and trained artefacts` | The differential that shows whether training changed behaviour outside its objective. |
| `Canary string inserted in training data` | A memorisation test: if the model can produce the canary, the data was retained. |
| `Adapter provenance and hash` | An adapter is a behaviour patch; its origin decides whether that patch is trusted. |
| `Dataset deduplication before training` | Reduces the chance that a single user's content dominates a behaviour class. |

## Worked Contrast

**Third-Party Adapter Loaded Without Evaluation:**

```python
adapter = load_adapter("hf://some-org/style-lora")   # BUG: no provenance, no hash, no evaluation
model.load_adapter(adapter)
serve(model)                                        # refusal behaviour never re-tested
```

**Verified Adapter With a Base-Versus-Trained Evaluation:**

```python
EXPECTED = manifest["adapter_sha256"]
actual = sha256_file("style-lora.safetensors")
if actual != EXPECTED:
    raise SystemExit("adapter hash mismatch")

base = run_safety_eval(base_model, "safety-eval.json")
tuned = run_safety_eval(base_model.with_adapter("style-lora.safetensors"), "safety-eval.json")
regressions = [c for c in base if base[c] != tuned.get(c)]
if regressions:
    raise SystemExit(f"refusal regressions: {regressions}")
```

**Why this matters:** An adapter from an unverified source can suppress refusals or add a trigger response with no change to the base weights, and nothing in the deployment would show it. Verifying the adapter hash and running the same safety evaluation against the base and the tuned model produces a per-case differential, so any behaviour change outside the intended style objective is visible before the artefact serves traffic.

## When It Is NOT This Issue

- **Adapter trained internally on curated data.** Provenance exists; the remaining check is the evaluation differential.
- **Style change after a style fine-tune.** The intended objective; the finding is a change outside that objective.
- **Canary not reproduced on a single prompt.** Memorisation tests need several prompt forms; one negative result is not conclusive.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `fine-tuning-and-lora-alignment-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `fine-tuning-and-lora-alignment-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: fine-tuning-and-lora-alignment-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-506 | Mapping: LLM04:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `fine-tuning-and-lora-alignment-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-506`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
