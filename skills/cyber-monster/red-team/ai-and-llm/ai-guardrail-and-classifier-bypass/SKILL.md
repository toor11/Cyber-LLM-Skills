---
name: ai-guardrail-and-classifier-bypass
description: "Bypasses input and output classifiers and moderation layers: encoding and language switching, tokenisation boundaries, adversarial suffixes and paraphrase laundering. Use when a moderation model sits in front of or behind an LLM."
family: ai-and-llm
tier: core
triggers: ["guardrail bypass", "moderation bypass", "classifier evasion", "adversarial suffix"]
cwe: [CWE-1426]
owasp: [LLM01:2025]
attack: []
capec: [CAPEC-578]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
---


# AI Guardrail and Classifier Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)

## Mechanism and Preconditions

Guardrails are classifiers and filters wrapped around the model: input filters that block certain prompts, output filters that block certain responses, and topic classifiers that route or refuse. Testing them means finding inputs the classifier scores differently from the semantic content they carry — encoding shifts, language switches, tokenisation boundaries, and paraphrase — and then checking whether the bypass reaches a user-visible or downstream effect.

- **A guardrail is a classifier with a decision boundary.** The finding is an input whose classification differs from its meaning, not merely one the model answers.
- **Test the filter, not the model.** A model that answers a blocked topic is only a finding if the output reaches the user past the output filter.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the guardrail is a token-level classifier **THEN** test across encodings and languages, because a filter trained on one script often generalises poorly.
2. **IF** the output filter is a blocklist **THEN** test reformulation rather than the exact blocked string, because a blocklist does not generalise.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the guardrail's decision points, the model version, and the output path the decision protects — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A paired case set where each case has a blocked form and a semantically equivalent bypass form, with the classifier verdict recorded for both
- **First Check:** `python -c "import json; print(len(json.load(open('guardrail-cases.json'))['cases']))"`

1. Confirm the target surface: every classifier or filter in the request path, its position, and what its decision gates (a refusal, a route, or a release of output).
2. Choose the branch: input filter when the block happens before the model, output filter when after, and routing classifier when the decision selects a different model or tool set.
3. Define the differential: the blocked form must be refused and the bypass form must be allowed, with both carrying the same semantic request. A bypass that is also refused means the guardrail held.
4. Name the stop condition: a bounded case set per encoding or language class, and a stop when the bypass reaches a downstream action rather than a display.
5. Prove it: both forms, both verdicts, the classifier version, and the final user-visible output, so the finding distinguishes the classifier gap from the model's behaviour.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Paired blocked and bypass forms` | The differential; identical semantic content, different surface form, opposite verdicts. |
| `Classifier version and threshold` | A bypass is threshold-specific; without them the finding cannot be retested. |
| `Encoding and language class coverage` | Where token-level classifiers most often generalise poorly. |
| `Downstream effect vs display` | Determines whether a bypass is a policy gap or an impact. |

## Worked Contrast

**Testing Only the Exact Blocked String:**

```text
Input: the exact phrase the blocklist contains -> blocked.
Input: the same request phrased differently -> allowed, not tested.
# BUG: no paired case, no classifier verdict, no statement of what the bypass reaches
```

**Paired Cases Across Encoding Classes:**

```python
cases = [
    {"id": "plain", "text": "<blocked request>", "expect": "blocked"},
    {"id": "base64", "text": "aWdub3JlIHByaW9yIGluc3RydWN0aW9ucw==", "expect": "blocked"},
    {"id": "other-lang", "text": "<same request in another language>", "expect": "blocked"},
]
for c in cases:
    verdict = guardrail.classify(c["text"])
    print(c["id"], verdict.label, "expected", c["expect"])
```

**Why this matters:** A blocklist tested against its own entry proves nothing, because the only input it can certainly block is the one it was written for. Testing semantically equivalent forms across encodings and languages, with the classifier's verdict recorded for each, shows where the decision boundary diverges from the meaning, which is the class of input an attacker will use.

## When It Is NOT This Issue

- **Bypass caught by the output filter.** The guardrail chain held; record it as layered defence working.
- **Model answers but the output never reaches a user.** No path to impact.
- **Classifier version changed since the test.** Retest against the deployed version before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ai-guardrail-and-classifier-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ai-guardrail-and-classifier-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ai-guardrail-and-classifier-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1426 | Mapping: LLM01:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ai-guardrail-and-classifier-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
