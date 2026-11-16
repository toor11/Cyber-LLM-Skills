---
name: ai-and-llm-application-defense
description: "Defends LLM applications: prompt injection mitigations, output handling, tool scoping and monitoring for abuse. Use when securing an AI feature rather than attacking it."
family: application-security
tier: core
triggers: ["llm defense", "ai application security defense", "prompt injection mitigation"]
cwe: [CWE-20]
owasp: [LLM01:2025]
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# AI and LLM Application Defense - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`llm-prompt-injection`](../../../red-team/ai-and-llm/llm-prompt-injection/SKILL.md)

## Mechanism and Preconditions

Defending an LLM feature means treating the model as an untrusted component inside your trust boundary: its output is data, its tools are privileged capabilities, and its context is an input channel an attacker can reach through documents, retrieved chunks, and tool results. The controls that hold are structural — scoped credentials per tool, egress allowlists, schema validation of model output before it reaches a sink, and separation between instructions and data. Prompt wording is not a control, and OWASP's 2026 list names the consequence directly: LLM08 Hidden Context Exposure now covers the assumption that system prompts and tool schemas stay secret.

- **CWE-20 framing:** model output, retrieved chunks, and tool results are untrusted input at the same boundary as a request body.
- OWASP GenAI LLM Top 10 2026 (published 4 August 2026) order: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the feature exposes tools or function calls **THEN** start with LLM03 Excessive Agency: enumerate every tool and its credential scope before discussing prompt hardening.
2. **IF** retrieval is involved **THEN** check tenant separation in the vector store (LLM09) before content filtering; cross-tenant retrieval is a data-disclosure defect, not a prompt problem.
3. **IF** the output is rendered or executed **THEN** apply the sink rules from `secure-code-review-injection-and-data-flow`; markdown-to-HTML and generated code are ordinary sinks.
4. **IF** the concern is cost or rate exhaustion **THEN** treat it as a quota problem (LLM06) with per-tenant budgets, not as a model behaviour problem.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Draw the boundary around the model call.** Everything that enters the context (user turn, retrieved chunks, tool results, memory, files) is attacker-reachable input; everything that leaves is untrusted output. Write both lists down before choosing controls.
2. **Enumerate the capabilities the model can invoke.** For each tool: the credential it uses, the actions it can take, whether it can reach the network, and whether a human must approve. Any tool with broader scope than the requesting user is an Excessive Agency finding.
3. **Choose the branch by sink.** Text rendered to a user takes the output-encoding branch; code or commands to execute take the sandbox branch; data writes take the schema-and-authorisation branch; retrieval takes the tenant-isolation branch.
4. **Define the baseline-vs-probe differential.** Baseline: a benign request whose retrieved documents contain no instructions. Probe: the same request with an injected instruction inside a retrieved document, a filename, or a tool result. A defended system's observable outcome (tool calls, egress, rendered output) must be unchanged by the probe.
5. **State the stop condition and the proof.** Stop when each capability has a scope smaller than the caller's, output reaches its sink through a validating path, and the injection probe changes nothing; proof is the tool-call log for the probe run, not the system prompt text.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Tool credential broader than the requesting user's scope | Proves excessive agency (LLM03:2026); a prompt injection now has the tool's privileges, not the user's. |
| Retrieved chunk from another tenant returned in context | Proves vector-store isolation is missing (LLM09:2026); metadata filters must be enforced server-side, not requested in the prompt. |
| Model output rendered as HTML or executed as code without validation | Proves improper output handling (LLM10:2026) reaching an ordinary sink. |
| Egress from the tool runtime to arbitrary hosts | Proves a markdown-image or link-fetch channel can exfiltrate context, and is the usual blind spot in agent deployments. |

## Worked Contrast

**Vulnerable tool wiring (model output decides the request, credentials are ambient):**

```python
@tool
def fetch_url(url: str) -> str:
    """Fetch a page the model chose."""
    return requests.get(url, timeout=5).text        # any host, ambient credentials

def answer(q: str, docs: list[str]) -> str:
    ctx = "\n".join(docs)                            # unfiltered, cross-tenant possible
    return llm.complete(f"{ctx}\nUser: {q}")         # instructions and data share one channel
```

**Hardened tool wiring (allowlisted egress, per-user scope, delimited data channel):**

```python
ALLOWED = {"docs.internal", "status.internal"}

@tool(requires_approval=False)
def fetch_url(url: str, *, caller: Principal) -> str:
    host = urlparse(url).hostname or ""
    if host not in ALLOWED:
        raise ToolDenied(f"host not allowed: {host}")
    return httpx.get(url, timeout=5, follow_redirects=False,
                     headers={"Authorization": f"Bearer {caller.scoped_token('docs.read')}"}).text

def answer(q: str, docs: list[Document], caller: Principal) -> str:
    kept = [d for d in docs if d.tenant_id == caller.tenant_id][:8]
    ctx = "\n\n".join(f"<doc id={d.id}>\n{d.text}\n</doc>" for d in kept)
    return llm.complete(system=SYS, data=ctx, user=q)   # separate roles, no interpolation
```

**Why this matters:** The first version gives the model an arbitrary-URL fetcher with ambient credentials and mixes retrieved text into the instruction channel, so one poisoned document becomes an instruction with network access. The second allowlists hosts, mints a token scoped to the caller, filters by tenant before the context is built, and passes data in a delimited block rather than concatenating it into the prompt.

## When It Is NOT This Issue

- **Model refused the injection during testing.** A single successful refusal is not a control; the finding depends on capability scope and sinks, which are deterministic.
- **Retrieval returns public content only.** Cross-tenant leakage needs tenants; a corpus of published documents does not create the LLM09 finding, though poisoning still applies.
- **System prompt contains no secrets.** Then LLM08 does not apply to that prompt; check tool schemas and memory stores instead of filing on the prompt text alone.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `ai-and-llm-application-defense` based solely on surface keywords (`input isolation`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ai-and-llm-application-defense` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: ai-and-llm-application-defense
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`llm-prompt-injection`](../../../red-team/ai-and-llm/llm-prompt-injection/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ai-and-llm-application-defense` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 3 |
| Top sources | OffsecCyber (11), CYBER_CPT/go_exploitdb (6), SecEval/cwe (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
