---
name: llm-data-exfiltration-and-leakage
description: "Extracts sensitive context from LLM applications: system prompt disclosure, training data memorisation, cross-tenant retrieval leakage and side-channel inference. Use when the model has access to confidential material."
family: ai-and-llm
tier: core
triggers: ["system prompt leak", "llm data leak", "training data extraction", "cross tenant llm"]
cwe: [CWE-200, CWE-359]
owasp: [LLM02:2025]
attack: []
capec: [CAPEC-118]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# LLM Data Exfiltration and Leakage - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Leakage from an LLM application takes several forms: the system prompt disclosed, training data memorised, one tenant's data retrieved by another, and inference about a record the model was trained on. The audit question is which of these is reachable and through what channel — a direct answer, a retrieval path, a tool, or an outbound request the model can influence.

- **Cross-tenant retrieval is the highest-impact case.** It is a data-boundary failure, not a model behaviour, so the test is two accounts and one query.
- **The system prompt is configuration, not a secret.** Treat disclosure as expected and check whether it contains credentials or business logic whose exposure is a real impact.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the application is multi-tenant **THEN** test retrieval with two accounts before any prompt-level test, because that path leaks real data rather than configuration.
2. **IF** the model can emit a URL or image reference **THEN** check whether the client fetches it automatically, which turns a text answer into an exfiltration channel.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the data stores the model can read, the principals who share them, and the outbound channels the output can trigger — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A two-account retrieval test, a system-prompt extraction attempt, and an outbound-channel review for model-influenced URLs
- **First Check:** `python -c "import json; print(json.load(open('tenants.json'))['accounts'])"`

1. Confirm the target surface: the data stores reachable by retrieval or tools, the tenant or ACL model, and every channel the output can reach (render, link, image, webhook).
2. Choose the branch: cross-tenant retrieval for multi-tenant stores, prompt disclosure for configuration exposure, and outbound-channel review when the client resolves references from output.
3. Define the differential: the same query from two accounts; the differential is a document or field present in one account's answer and absent in the other's.
4. Name the stop condition: two accounts return disjoint data sets for the same query, and no model-influenced URL is fetched without an allowlist.
5. Prove it: the query, both answers with their retrieved chunk ids, and the account each was made under, so the leak is attributable.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Two-account retrieval differential` | The direct test for a data-boundary failure; it exercises real data rather than model behaviour. |
| `System prompt extraction attempt` | Establishes whether configuration is disclosed and whether it contains anything sensitive. |
| `Model-influenced URL in output` | An exfiltration channel when the client or a renderer fetches it automatically. |
| `Chunk ids in the answer metadata` | Makes the retrieved set auditable and a leak attributable to a specific document. |

## Worked Contrast

**Shared Retrieval With Client-Side Tenant Filtering:**

```python
hits = index.search(query_vector, top_k=10)          # BUG: no tenant filter
context = "\n".join(h.text for h in hits)
answer = model.complete(context + "\n" + question)
if caller.tenant not in [h.tenant for h in hits]:
    pass  # BUG: noting the mismatch does not undo the disclosure already in the answer
```

**Tenant-Filtered Retrieval With an Outbound Allowlist:**

```python
hits = index.search(query_vector, top_k=10, filter={"tenant": caller.tenant})
assert all(h.tenant == caller.tenant for h in hits)
context = "\n".join(f"<chunk id={h.id}>\n{h.text}\n</chunk>" for h in hits)
answer = model.complete(context + "\n" + question)

# Any URL in the answer must be on the allowlist before the client resolves it.
for url in extract_urls(answer):
    if not allowlist.permits(url):
        raise PermissionError(f"blocked outbound reference: {url}")
```

**Why this matters:** A post-hoc tenant check cannot undo a disclosure that is already in the model's answer, and a model-influenced URL that the client fetches becomes an exfiltration channel for anything else in the context. Filtering inside the retrieval query prevents the cross-tenant chunk from entering at all, and an allowlist on outbound references stops the answer from being used to leak context to an attacker-controlled host.

## When It Is NOT This Issue

- **System prompt disclosed but containing no secrets.** Configuration exposure with no credential or business-logic impact is a hardening note.
- **Model refuses a cross-tenant request.** Refusal is not a control; the test is whether the data was in the context.
- **Memorisation claim without a unique canary.** A model producing plausible text is not evidence of memorisation; use a canary inserted into training data.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `llm-data-exfiltration-and-leakage` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `llm-data-exfiltration-and-leakage` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: llm-data-exfiltration-and-leakage
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200, CWE-359 | Mapping: LLM02:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `llm-data-exfiltration-and-leakage` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200, CWE-359`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
