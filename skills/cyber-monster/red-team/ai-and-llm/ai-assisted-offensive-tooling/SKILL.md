---
name: ai-assisted-offensive-tooling
description: "Uses AI assistants deliberately in offensive work: payload variation, reconnaissance summarisation, code generation and triage, with verification discipline. Use when accelerating repetitive analysis."
family: ai-and-llm
tier: leaf
triggers: ["ai assisted pentest", "llm for recon", "ai payload generation", "automation with llm"]
cwe: [CWE-1426]
owasp: []
attack: []
capec: [CAPEC-116]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# AI Assisted Offensive Tooling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Using a model as an assistant inside an assessment: summarising recon, drafting test cases, triaging scanner output, and generating variants of a probe. The engineering discipline is that the model's output is a draft from an untrusted source — it can invent an endpoint, cite a vulnerability that does not exist, or produce a payload that does something different from what it claims — so every output must be verified against the target before it enters a report.

- **The model does not know the target.** Its output is a hypothesis phrased confidently; the verification step is what makes it evidence.
- **Generated probes need review before execution.** A payload the model composed may be destructive or out of scope, and the authorisation belongs to the human who runs it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the model cites a CVE or a URL **THEN** verify it against the vendor advisory before it enters any deliverable, because plausible identifiers are the model's most common fabrication.
2. **IF** the model drafts a payload **THEN** read it for scope and destructiveness before running it, and never run a generated payload against a target outside the authorisation.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a defined task where the model's output is a draft, and a verification step that does not involve the model — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A prompt template with the target context supplied explicitly, and a verification checklist applied to every output before use
- **First Check:** `python -c "import json; print(len(json.load(open('assist-log.json'))['entries']))"`

1. Confirm the target surface: the task the model is assisting with, the context it is given, and the verification source for its output.
2. Choose the branch: summarisation when the input is collected data, drafting when the output is a test case, and triage when the output is a classification of scanner findings.
3. Define the differential: compare the model's claim with the primary source — the advisory, the endpoint response, or the scanner's own evidence; the differential is a claim that does not survive the check.
4. Name the stop condition: every factual claim verified, and every generated payload reviewed by a human before execution.
5. Prove it: the assist log records the prompt, the model output, the verification result, and who accepted it, so the report's provenance includes the model's contribution.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Prompt that includes the actual collected data` | Reduces invention; a model asked about a target it cannot see will produce plausible detail. |
| `Verification against the vendor advisory` | The only acceptable source for a CVE claim; a model-cited identifier is unverified by default. |
| `Human review of generated payloads` | The scope and destructiveness check belongs to the person who runs the probe. |
| `Assist log with the accepted output` | Distinguishes human findings from model drafts when the deliverable is reviewed. |

## Worked Contrast

**Model Output Pasted Into the Report:**

```text
Ask the model to summarise the scan results and list the vulnerabilities.
Paste the summary into the deliverable.
# BUG: no verification, no CVE check, no distinction between the model's draft and observed evidence
```

**Model Draft With a Verification Record:**

```text
Prompt: here are 40 scanner findings (JSON) and the endpoint list; group them by likely root cause.
Model draft: 6 groups, with two CVE references.
Verification: CVE-2026-0000 checked against the vendor advisory (not applicable, version out of range) -> dropped.
Remaining groups confirmed against the scanner evidence and one manual request each.
Assist log: prompt hash, draft, verification notes, accepting analyst.
```

**Why this matters:** A model summarising a JSON file produces a confident narrative that includes invented identifiers, and pasting it into a deliverable transfers the model's errors to the client. Verifying each CVE against the advisory and each group against the scanner's own evidence keeps only the claims that survive, and the assist log records which parts of the report came from a draft.

## When It Is NOT This Issue

- **Model output used as a prompt for human analysis.** A draft that a human then verifies is the intended use.
- **Invented identifier caught before delivery.** The verification step worked; record it rather than treating the invention as a finding.
- **Model summarising data the analyst already has.** Summarisation of supplied context is low risk; fabrication rises when the model must supply facts.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ai-assisted-offensive-tooling` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ai-assisted-offensive-tooling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ai-assisted-offensive-tooling
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1426 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ai-assisted-offensive-tooling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
