---
name: ai-application-assessment
description: "Runs an end-to-end assessment of an AI application: data flow mapping, prompt surface review, output trust boundaries, tool permissions and monitoring gaps. Use when scoping an LLM application test."
family: ai-and-llm
tier: core
triggers: ["llm application assessment", "ai app pentest", "ai threat model", "ai security review"]
cwe: [CWE-1426]
owasp: [LLM01:2025]
attack: []
capec: [CAPEC-116]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
---


# AI Application Assessment - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)

## Mechanism and Preconditions

A structured assessment of an LLM application walks four surfaces in order: the prompt and context assembly (what reaches the model), the output path (where the response goes), the tool scope (what the model can invoke), and the data flow (what the model can read). The review produces a map from each surface to the control that bounds it, which is what an assessor needs to judge whether an impact is reachable.

- **Four surfaces, one order.** Prompt, output, tools, data — assessed in that sequence, because each later surface's risk depends on whether the earlier one is bounded.
- **Every surface needs a deterministic control.** A model-side instruction is not a control; the control is a validator, an allowlist, a scoped credential, or a query filter.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the application renders model output **THEN** the output surface is the first priority, because that is where text becomes markup, a query, or a command.
2. **IF** the application has tools **THEN** map each tool to the credential it uses, because the tool list with credentials is the effective privilege of the model.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the four surfaces mapped, each with the control that bounds it — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A surface map with the control per surface, and a test case per surface that exercises the control
- **First Check:** `python -c "import yaml; print(sorted(yaml.safe_load(open('surface-map.yaml'))['surfaces']))"`

1. Confirm the target surface: enumerate the prompt path, the output sinks, the tool list with credentials, and the data stores the application can read.
2. Choose the branch: output-focused assessment when responses are rendered or executed, tool-focused when the model can act, and data-focused when the model retrieves from a multi-tenant store.
3. Define the differential: for each surface, a benign request and a probe that exercises the control; the differential is the probe being stopped by a deterministic control rather than by model discretion.
4. Name the stop condition: every surface has either a deterministic control or a documented accepted risk with the impact named.
5. Prove it: the surface map, the control per surface, and the probe result showing the control acted, so the assessment is a matrix rather than a list of prompts.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Prompt assembly with labelled untrusted sections` | Makes the trust boundary explicit and testable rather than implied by wording. |
| `Output sink inventory` | Where the response is rendered, stored, executed, or queried; each sink is a distinct impact. |
| `Tool list with credential per tool` | The model's effective privilege, which is usually larger than the application's own role model suggests. |
| `Data store scope per query path` | Whether retrieval is filtered before ranking, which decides cross-tenant reachability. |

## Worked Contrast

**Prompt-Only Assessment:**

```text
Test twenty jailbreak prompts.
Report: the model refused 18 of 20, so the application is low risk.
# BUG: no output, tool or data surface assessed; refusal rate on prompts says nothing about impact
```

**Surface Matrix With Controls:**

```yaml
surfaces:
  prompt:
    control: untrusted sections delimited and labelled; no tool authority on the retrieval path
    probe: injected document -> no tool call
  output:
    control: HTML escaped at render; no innerHTML sink
    probe: markdown with script tag -> rendered as text
  tools:
    control: intent-only schemas; per-user delegated token
    probe: hijacked context -> payment proposed, not executed
  data:
    control: tenant filter inside the vector query
    probe: foreign chunk present -> not retrieved
```

**Why this matters:** A refusal rate measures the model's disposition, and an application can refuse every jailbreak while still rendering model output as HTML. Assessing each surface with a probe that exercises a deterministic control produces a matrix where the gaps are visible, and each gap has a named impact rather than a prompt score.

## When It Is NOT This Issue

- **Jailbreak that produces only text the user sees.** Without an output, tool, or data surface, the impact is limited to the requester.
- **Tool present but not reachable from the assessed path.** A tool on a different agent has its own assessment.
- **Refusal rate used as the risk measure.** Refusal is one signal, not a control; the control is what bounds the surface.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `ai-application-assessment` based solely on surface keywords (`prompt surface`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ai-application-assessment` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: ai-application-assessment
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-1426`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) - Blue Detection/Defense Counterpart
- [`llm-prompt-injection`](../llm-prompt-injection/SKILL.md) - AI and LLM (flagship)
- [`llm-jailbreak-and-guardrails`](../llm-jailbreak-and-guardrails/SKILL.md) - AI and LLM (core)
- [`rag-and-vector-store-attacks`](../rag-and-vector-store-attacks/SKILL.md) - AI and LLM (core)
- [`agentic-ai-and-mcp-security`](../agentic-ai-and-mcp-security/SKILL.md) - AI and LLM (core)
- [`model-and-artifact-supply-chain`](../model-and-artifact-supply-chain/SKILL.md) - AI and LLM (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ai-application-assessment` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (6), OffsecCyber (3), CYBER_CPT/go_exploitdb (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
