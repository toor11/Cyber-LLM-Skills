---
name: ai-agent-and-llm-telemetry-hunting
description: "Hunts for prompt injection, tool-call confused-deputy abuse, and RAG data exfiltration across LLM gateway logs: abnormal tool-invocation sequences, cross-tenant retrieval spikes, outbound markdown image/link rendering, and high-entropy prompt bursts. Use when hunting threats in enterprise GenAI deployments."
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["hunt llm abuse", "ai agent telemetry hunting", "mcp tool anomaly", "rag exfiltration hunt"]
cwe: [CWE-200]
owasp: [LLM01:2025, LLM06:2025]
attack: []
capec: []
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
corpus_sparse: true
---

# AI Agent and LLM Telemetry Hunting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`rag-and-vector-store-attacks`](../../../red-team/ai-and-llm/rag-and-vector-store-attacks/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Hunting AI-agent activity means looking for behaviour that a model-driven system produces when it is manipulated or misconfigured: tool calls outside the caller's entitlement, retrieval returning another tenant's chunks, outbound fetches to hosts the workload never used, and token consumption spikes. The telemetry is new and often incomplete, so the first hunt is usually about what the platform emits rather than what it contains. OCSF 1.9.0 (August 2026) added AI-agent and delegation support plus record-integrity attestation, which is the emerging schema vocabulary for these events.

- **CWE-778 / CWE-200:** the failure is a decision or data access that leaves no attributable record - for example a tool call logged without the caller identity or the credential scope used.
- OWASP GenAI LLM Top 10 2026 lists Excessive Agency third and Hidden Context Exposure eighth, both of which are visible in tool-call and context-assembly telemetry rather than in model output.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is whether the application is defended **THEN** open `ai-and-llm-application-defense`, which owns the controls.
2. **IF** the finding is a prompt-injection attempt in a payload **THEN** the prompt-injection skill owns the technique; this skill owns the telemetry hunt.
3. **IF** the telemetry does not exist yet **THEN** the first output is an onboarding requirement, not a hunt result.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory what the platform emits.** Tool calls with caller identity and credential scope, retrieval results with tenant metadata, context assembly events, token usage, and outbound fetches. Note which of those carry an identity, because the hunt depends on it.
2. **Establish the baseline per agent.** Tool-call frequency by tool, typical token consumption per request, and the normal set of outbound destinations. Without this, spikes are indistinguishable from growth.
3. **Choose the branch on the anomaly type.** Scope anomaly takes the entitlement-comparison branch; retrieval anomaly takes the tenant-isolation branch; egress anomaly takes the destination-provenance branch; volume anomaly takes the quota branch.
4. **Define the baseline-vs-probe differential.** Baseline: the same query over a period with no known manipulation. Probe: a staging run with an injected document. The observable (tool sequence, egress destination, token count) must differ; if it does not, the telemetry cannot answer the question.
5. **State the stop condition and the proof.** Stop when the hypothesis is answered or declared unanswerable with the missing field named; proof is the query output plus the staging differential.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Tool call whose credential scope exceeds the caller's entitlement | Proves excessive agency in operation, which is the highest-impact AI finding because it converts a prompt into an authorised action. |
| Retrieval result whose tenant differs from the request tenant | Proves vector-store isolation failure; the data leaves the tenant boundary before any output filter. |
| Outbound fetch from the tool runtime to a host outside the allowlist | Proves an exfiltration channel, commonly triggered through a markdown image or link preview. |
| Token consumption spike correlated with a long retrieved document | Proves context flooding, which is a cost and a manipulation vector rather than a crash. |

## Worked Contrast

**Hunt on model output text:**

```text
Query: search LLM response logs for 'ignore previous instructions'
Result: 3 hits, all in test traffic
Conclusion: no prompt injection in production
Note: tool calls are not logged; retrieval tenant is not recorded
```

**Hunt on tool-call and retrieval telemetry with a staging differential:**

```text
Telemetry inventory
  tool_calls      : tool.name, caller.id, credential.scope, args_hash     (present)
  retrieval       : chunk.tenant_id, request.tenant_id, chunk.source      (tenant present, source missing)
  egress          : network.destination, process.image                     (present)
  context         : assembled token count, chunk ids                       (present)
  MISSING         : tool result content (cannot see what the model received)

Baseline (agent=invoice-assistant, 2026-10-01..2026-11-01)
  tools: search_docs 92%, create_ticket 6%, fetch_url 2% (destinations: docs.internal only)
  tokens: p50 3.1k, p99 9.4k per request

Probe (same agent, 2026-11-01..2026-11-13)
  fetch_url 11% of calls, destinations include 3 external hosts (one not in allowlist)
  one call: caller=finance.user4, credential.scope=[docs.read, crm.write] (caller lacks crm.write)
  retrieval: 2 requests returned chunks with tenant_id != request.tenant_id

Staging differential: injected document in retrieved set -> fetch_url called with an external URL.
Verdict: telemetry answers scope and retrieval questions, not content questions (gap: SEC-6741).
```

**Why this matters:** The first hunt searches output text, which is the least reliable place to find injection, and its own note admits the two fields that matter are absent. The second inventories what exists, establishes a baseline per agent, and finds three separate anomalies in scope, egress, and retrieval - while explicitly recording the content gap that limits the conclusion.

## When It Is NOT This Issue

- **Token spike during a marketing campaign.** Volume anomalies need a business-context check before they are findings.
- **Tool call with broad scope that matches the caller's role.** Scope breadth is only a finding relative to the caller's entitlement, not in absolute terms.
- **Retrieval returning a shared public document.** Tenant mismatch matters only for tenant-owned corpora; check the corpus class.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `tool_call sequence anomaly` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ai-agent-and-llm-telemetry-hunting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ai-agent-and-llm-telemetry-hunting
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / LLM01:2025, LLM06:2025]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`rag-and-vector-store-attacks`](../../../red-team/ai-and-llm/rag-and-vector-store-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`hypothesis-driven-hunting`](../hypothesis-driven-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ai-agent-and-llm-telemetry-hunting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
