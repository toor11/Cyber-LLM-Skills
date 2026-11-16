---
name: rag-and-vector-store-attacks
description: "Attacks retrieval augmented generation: poisoning the vector store, embedding inversion, chunk boundary injection and retrieval ranking manipulation. Use when the application retrieves documents before generation."
family: ai-and-llm
tier: core
triggers: ["rag attack", "vector store poisoning", "embedding inversion", "retrieval poisoning"]
cwe: [CWE-200, CWE-1426]
owasp: [LLM04:2025]
attack: []
capec: [CAPEC-442]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, agentic-ai-and-mcp-security, model-and-artifact-supply-chain]
corpus_sparse: true
---


# RAG and Vector Store Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`ai-agent-and-llm-telemetry-hunting`](../../../blue-team/threat-intelligence-and-hunting/ai-agent-and-llm-telemetry-hunting/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Retrieval-augmented generation introduces a data store the model trusts: chunks are embedded, indexed, and retrieved by similarity, then placed in the context. The attack surface is the ingestion path (who can write into the index), the retrieval filter (whether tenant or ACL constraints are applied before ranking), and the ranking itself (whether an attacker can make a chunk appear for queries it does not answer).

- **Ingestion is the trust boundary.** Anyone who can write a document into the index can place text in the context of every user whose query retrieves it.
- **Filter before ranking, not after.** A tenant filter applied to the top-k results lets a cross-tenant chunk occupy a slot and leak through ranking metadata or the model's answer.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the index is shared across tenants **THEN** verify the metadata filter is applied in the vector query, not to the returned list.
2. **IF** documents are ingested from an untrusted source **THEN** the content is a prompt-injection path as well as a data path, so both the retrieval filter and the instruction boundary matter.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-agent-and-llm-telemetry-hunting`](../../../blue-team/threat-intelligence-and-hunting/ai-agent-and-llm-telemetry-hunting/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the ingestion path, the retrieval query with its filter, and the context assembly code — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A vector store queried with an explicit metadata filter in the search call, and an ingestion pipeline that records the source and owner of every chunk
- **First Check:** `python -c "import json; print(json.load(open('query.json'))['filter'])"`

1. Confirm the target surface: the ingestion sources, the embedding model, the vector query including its filter, and how retrieved chunks are assembled into the context.
2. Choose the branch: ingestion review when untrusted writers exist, filter review when the store is multi-tenant, and ranking review when an attacker can influence embeddings.
3. Define the differential: run the same query with and without a foreign-tenant chunk present; the differential is a retrieved chunk, or an answer, that depends on data the caller should not reach.
4. Name the stop condition: every retrieval applies owner filtering inside the vector query, and no retrieved chunk can be attributed to another tenant.
5. Prove it: the query object with its filter, the retrieved chunk ids with owners, and the assembled context, so the leak path is visible end to end.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Filter clause inside the vector search call` | The only placement that prevents a foreign chunk from consuming a top-k slot. |
| `Chunk metadata with source and owner` | Makes attribution checkable; a chunk without an owner cannot be filtered reliably. |
| `Ingestion authorisation per source` | Decides who can place text in the context; an open ingestion path is the primary finding. |
| `Context assembly showing chunk boundaries` | Without boundaries the model cannot distinguish content from instruction, which compounds the leak. |

## Worked Contrast

**Filter Applied After Retrieval:**

```python
hits = index.search(query_vector, top_k=10)  # BUG: no owner filter in the query
allowed = [h for h in hits if h.metadata["tenant"] == caller.tenant]  # BUG: post-filter
# A foreign chunk occupies a slot in top_k, so the caller's own results are crowded out
# and any ranking metadata leaked with the hit reveals another tenant's content
```

**Filter Inside the Query With Attributed Chunks:**

```python
hits = index.search(
    query_vector,
    top_k=10,
    filter={"tenant": caller.tenant, "acl": {"$in": caller.groups}},
)
rows = []
for h in hits:
    rows.append({"chunk": h.id, "tenant": h.metadata["tenant"], "source": h.metadata["source"]})
assert all(r["tenant"] == caller.tenant for r in rows), "cross-tenant chunk retrieved"
```

**Why this matters:** A post-retrieval filter cannot undo the fact that a foreign chunk occupied a result slot: it either crowds out the caller's own results or leaks through whatever metadata travels with the hit. Applying the owner and ACL filter inside the search restricts the candidate set before ranking, and asserting every returned chunk's tenant catches a filter that was silently dropped.

## When It Is NOT This Issue

- **Shared public corpus with no tenant data.** A single-tenant index has nothing to leak across tenants.
- **Chunk retrieved but never placed in the context.** Truncation may discard it; check the assembly step before reporting a leak.
- **Similarity match on generic phrases.** Low-quality retrieval is a relevance problem, not a security finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `rag-and-vector-store-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rag-and-vector-store-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: rag-and-vector-store-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200, CWE-1426 | Mapping: LLM04:2025]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ai-agent-and-llm-telemetry-hunting`](../../../blue-team/threat-intelligence-and-hunting/ai-agent-and-llm-telemetry-hunting/SKILL.md) - Blue Detection/Defense Counterpart
- [`llm-prompt-injection`](../llm-prompt-injection/SKILL.md) - AI and LLM (flagship)
- [`llm-jailbreak-and-guardrails`](../llm-jailbreak-and-guardrails/SKILL.md) - AI and LLM (core)
- [`agentic-ai-and-mcp-security`](../agentic-ai-and-mcp-security/SKILL.md) - AI and LLM (core)
- [`model-and-artifact-supply-chain`](../model-and-artifact-supply-chain/SKILL.md) - AI and LLM (leaf)
- [`ml-adversarial-and-data-poisoning`](../ml-adversarial-and-data-poisoning/SKILL.md) - AI and LLM (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rag-and-vector-store-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200, CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
