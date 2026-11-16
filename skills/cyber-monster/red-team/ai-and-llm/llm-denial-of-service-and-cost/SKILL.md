---
name: llm-denial-of-service-and-cost
description: "Assesses resource and cost exhaustion in LLM systems: unbounded context growth, recursive tool loops, expensive prompt amplification and rate-limit gaps. Use when availability or billing is a concern."
family: ai-and-llm
tier: leaf
triggers: ["llm denial of service", "token exhaustion", "cost abuse llm", "unbounded context"]
cwe: [CWE-400, CWE-770]
owasp: [LLM10:2025]
attack: []
capec: [CAPEC-125]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# LLM Denial of Service and Cost - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Unbounded consumption in an LLM application comes from the cost model rather than a classic resource exhaustion: long contexts, agent loops that re-enter tools, high-token outputs, and missing per-user quotas. The audit question is which request parameters a user controls, what the worst-case cost of one request is, and whether any quota or loop bound exists outside the model's discretion.

- **Cost is the denial vector.** A request that costs a hundred times the median is a denial of service against the budget and the rate limit, even if the service stays up.
- **Agent loops need a hard bound.** A loop that continues while the model chooses to call another tool has no natural limit; the bound must be a counter in code.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the user controls `max_tokens`, context length, or the number of turns **THEN** compute the worst-case cost per request and compare it with the quota.
2. **IF** the application runs an agent loop **THEN** look for a step counter and a total token budget, because a model-driven termination condition is not a bound.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the user-controlled request parameters, the worst-case cost per request, and the quota enforcement point — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Server-enforced `max_tokens`, context truncation, per-user request and token quotas, and a hard iteration counter on agent loops
- **First Check:** `python -c "import json; print(json.load(open('limits.json'))['max_tokens'], json.load(open('limits.json'))['steps'])"`

1. Confirm the target surface: which request fields the user controls, how context is assembled and truncated, and where quotas are enforced.
2. Choose the branch: parameter abuse when the user controls output length or context, loop abuse when tools can re-enter, and quota review when limits are enforced only in the client.
3. Define the differential: send the median request and the worst-case request from the same account; the differential is cost per request and whether the quota stops the second.
4. Name the stop condition: a server-side cap on every cost-bearing parameter and a counter that terminates agent loops regardless of model output.
5. Prove it: the two requests, their token accounting, and the quota response, so the worst-case cost and the enforcement point are both demonstrated.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Server-side `max_tokens`` | The output length cap; a client-supplied value is a suggestion. |
| `Context truncation before the call` | Bounds input cost; unbounded document inclusion is the most common cost amplifier. |
| `Per-user token quota enforced at the gateway` | Stops a single account from consuming the shared budget. |
| `Hard iteration counter for agent loops` | Terminates regardless of what the model decides, which is the only reliable bound. |

## Worked Contrast

**Client-Controlled Limits and a Model-Driven Loop:**

```python
def handle(req):
    while True:
        out = model.complete(req.prompt, max_tokens=req.max_tokens)  # BUG: client sets the cap
        if not out.tool_calls:
            break                      # BUG: termination depends on model output
        run_tools(out.tool_calls)      # BUG: no step counter, no token budget
    return out.text
```

**Server Caps With a Hard Step and Token Budget:**

```python
MAX_STEPS = 6
MAX_TOKENS = 1200

def handle(req, user):
    if quota.exceeded(user):
        raise PermissionError("quota exceeded")
    used = 0
    for step in range(MAX_STEPS):
        out = model.complete(truncate(req.prompt), max_tokens=MAX_TOKENS)
        used += out.usage.total_tokens
        if used > MAX_TOKENS * MAX_STEPS:
            break
        if not out.tool_calls:
            return out.text
        run_tools(out.tool_calls)
    return "step budget exhausted"
```

**Why this matters:** Allowing the client to set `max_tokens` and letting the model decide when to stop gives a request unbounded cost, because the only termination condition is the model's own output. A server-side cap, a per-user quota check before the call, and a loop counter with a total token budget bound the worst case regardless of what the model produces.

## When It Is NOT This Issue

- **Single expensive request from a legitimate user.** Cost without repetition is usage, not denial; the finding needs a repeatable amplification.
- **Client-side rate limit displayed in the UI.** It is not enforcement, but the finding is the missing server check rather than the UI.
- **Long context required by the task.** A documented requirement with a quota that accounts for it is a design choice.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `llm-denial-of-service-and-cost` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `llm-denial-of-service-and-cost` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: llm-denial-of-service-and-cost
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-400, CWE-770 | Mapping: LLM10:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `llm-denial-of-service-and-cost` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-400, CWE-770`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
