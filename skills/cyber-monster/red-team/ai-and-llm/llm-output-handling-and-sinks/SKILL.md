---
name: llm-output-handling-and-sinks
description: "Exploits unsafe handling of model output: markdown and HTML injection into rendered chat, generated code executed downstream, model output used in SQL or shell, and citation spoofing. Use when generated text flows into another interpreter."
family: ai-and-llm
tier: core
triggers: ["llm output injection", "markdown injection chat", "generated code execution", "output sink"]
cwe: [CWE-79, CWE-94]
owasp: [LLM05:2025]
attack: []
capec: [CAPEC-242]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
---


# LLM Output Handling and Sinks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)

## Mechanism and Preconditions

Model output is untrusted text that the application often treats as trusted: rendered as HTML, executed as code, interpolated into a SQL or shell command, or used as a URL. The audit question is which sink receives the output and whether that sink has a deterministic control, because the model cannot be relied on to produce safe text and prompt instructions cannot be a sanitiser.

- **The sink determines the vulnerability class.** The same output is XSS in a browser, SQL injection in a query, and command injection in a shell; assess the sink, not the text.
- **Model-side instructions are not encoding.** A system prompt asking for safe output does not escape anything, and a filter that strips one pattern is bypassed by reformulation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the output reaches a browser **THEN** check for an escaping step at render and a CSP, because markdown-to-HTML conversion often passes raw HTML through.
2. **IF** the output reaches a query or a command **THEN** the model output must be a parameter, never a fragment of the statement or the command line.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the sink inventory with the control at each sink — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Sink-specific encoding (HTML escape at render, parameter binding for queries, argument arrays for processes) and a CSP as a second layer
- **First Check:** `python -c "import yaml; print(sorted(yaml.safe_load(open('sinks.yaml'))['sinks']))"`

1. Confirm the target surface: every place model output is consumed (render, store, execute, query, fetch) and the library that consumes it.
2. Choose the branch: HTML sink for rendering, query sink for database access, command sink for process execution, and URL sink for link generation or fetching.
3. Define the differential: send the same benign output and a probe containing the sink's metacharacters; the differential is the control acting (escaped, parameterised) versus the metacharacter taking effect.
4. Name the stop condition: every sink has an encoding or binding step that does not depend on the model's output being well-formed.
5. Prove it: the raw output, the transformed text at the sink, and the result showing the metacharacter is inert, so the control is demonstrated rather than assumed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Escaping at render rather than at generation` | Applies to any output the model produces, including text it was instructed not to produce. |
| `Parameter binding for model-derived values` | The only control that holds when the output is used inside a query. |
| `Argument array for process execution` | Prevents shell metacharacters in model output from being interpreted. |
| `Content-Security-Policy as a second layer` | Bounds the impact of an escaping gap without replacing the escaping. |

## Worked Contrast

**Model Output Rendered and Queried Raw:**

```python
html = markdown_to_html(model_output)          # BUG: raw HTML in the output passes through
page.render(html)

rows = db.execute(f"SELECT * FROM t WHERE name = '{model_output}'")  # BUG: string interpolation
```

**Escaped at Render and Bound at the Query:**

```python
import html
import re

safe = html.escape(markdown_to_text(model_output))  # no raw HTML survives
page.render(f"<div>{safe}</div>")

rows = db.execute("SELECT * FROM t WHERE name = ?", (model_output,))  # bound parameter
```

**Why this matters:** A markdown renderer that passes raw HTML through turns a model response into script in the victim's browser, and interpolating the same response into a query makes it a SQL fragment. Escaping the text before rendering and binding the value as a parameter remove both, and neither depends on the model having produced benign output.

## When It Is NOT This Issue

- **Output rendered as plain text.** No sink, no injection; a `<script>` in a text node is inert.
- **Value bound as a parameter.** Parameterisation is the control; a bound value is not a vulnerability even when it contains quotes.
- **Markdown sanitised by a maintained library.** A sanitiser that allowlists tags is a valid control; check its configuration rather than the presence of markdown.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `llm-output-handling-and-sinks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `llm-output-handling-and-sinks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: llm-output-handling-and-sinks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79, CWE-94 | Mapping: LLM05:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `llm-output-handling-and-sinks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, CWE-94`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/gh_advisories (2), CYBER_CPT/hacktricks (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
