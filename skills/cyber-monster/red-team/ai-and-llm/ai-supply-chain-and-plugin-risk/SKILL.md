---
name: ai-supply-chain-and-plugin-risk
description: "Assesses plugin, extension and tool-integration risk in AI systems: third-party tool trust, credential delegation to plugins and prompt-injectable tool descriptions. Use when an AI product integrates external tools."
family: ai-and-llm
tier: leaf
triggers: ["ai plugin risk", "tool integration security", "third party ai tool"]
cwe: [CWE-1426]
owasp: [LLM03:2025]
attack: []
capec: [CAPEC-437]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, agentic-ai-and-mcp-security]
corpus_sparse: true
---


# AI Supply Chain and Plugin Risk - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

The plugin, extension, and tool-supply surface of an AI application: which third-party components the model can invoke, what credentials each receives, and whether their descriptions and behaviour can change after approval. The characteristic risks are a plugin holding delegated credentials beyond the user's authority, a plugin description steering tool selection, and a plugin whose endpoint changes after review.

- **Credential delegation is the impact.** A plugin with a token that can read more than the requesting user is a privilege escalation path, regardless of how the model behaves.
- **Descriptions are prompt content.** A plugin's manifest text reaches the model, so a mutable description can change tool selection without any code change.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a plugin receives a credential **THEN** compare its scopes with the requesting user's authority, because that difference is the escalation.
2. **IF** the manifest can be updated remotely **THEN** pin its hash and require re-approval on change, or the approval covers a component that no longer exists.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the plugin inventory, the credential per plugin, and the manifest pinning mechanism — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Per-user delegated credentials for every plugin, manifest hashes pinned at approval, and an egress allowlist for plugin endpoints
- **First Check:** `python -c "import yaml; print(yaml.safe_load(open('plugins.yaml'))['plugins'])"`

1. Confirm the target surface: every plugin the model can invoke, the credential it receives, the scopes that credential carries, and where its manifest is fetched from.
2. Choose the branch: credential review for delegated authority, manifest review for mutable descriptions, and behaviour review for a plugin whose response is treated as trusted data.
3. Define the differential: invoke the plugin as a limited user and as a privileged one; the differential is a result the limited user should not receive.
4. Name the stop condition: every plugin credential is scoped to the requesting user, and every manifest is pinned by hash.
5. Prove it: the plugin call with the credential used, the scopes it carried, and the result, so the escalation path is shown rather than inferred.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Plugin credential scopes versus user scopes` | The comparison that identifies a plugin as a privilege escalation path. |
| `Manifest hash pinned at approval` | Prevents a description change from altering tool behaviour after review. |
| `Plugin response treated as untrusted data` | A compromised plugin's output is prompt input, not a trusted instruction. |
| `Endpoint allowlist for plugin calls` | Bounds where a plugin can send whatever data it receives. |

## Worked Contrast

**Plugin With a Service Account and a Remote Manifest:**

```yaml
plugins:
  - name: crm-lookup
    endpoint: https://plugins.example/crm
    credential: service-account-crm-full  # BUG: broader than any requesting user
    manifest: https://plugins.example/crm/manifest.json  # BUG: mutable, not pinned
```

**Per-User Credential With a Pinned Manifest:**

```yaml
plugins:
  - name: crm-lookup
    endpoint: https://plugins.example/crm
    credential: delegated-per-user  # scopes intersect the user's own grants
    manifest_sha256: 9f2c41e7b3a8d5c6f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70
    egress_allowlist: ["plugins.example"]
```

**Why this matters:** A plugin holding a full-access service account turns every model invocation into an action with more authority than the user who asked for it, and a manifest fetched at runtime can be changed to steer tool selection after the approval review. Delegating the user's own scopes and pinning the manifest hash keeps the plugin inside the requester's authority and inside the component that was reviewed.

## When It Is NOT This Issue

- **Plugin with a service account and no user data access.** The scope mismatch matters only when the credential can reach data beyond the user.
- **Manifest fetched at startup from a signed endpoint.** The signature is the pin; check it rather than the fetch.
- **Plugin failure that returns an error.** An error path is not an escalation.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ai-supply-chain-and-plugin-risk` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ai-supply-chain-and-plugin-risk` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ai-supply-chain-and-plugin-risk
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1426 | Mapping: LLM03:2025]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ai-supply-chain-and-plugin-risk` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
