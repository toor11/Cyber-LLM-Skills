---
name: agentic-ai-and-mcp-security
description: "Assesses agentic systems and tool protocols: tool permission scope, confused deputy paths, MCP server trust, and autonomous action chains. Use when a model can call tools, browse or act on external systems."
family: ai-and-llm
tier: core
triggers: ["agentic ai security", "mcp security", "tool abuse agent", "confused deputy ai"]
cwe: [CWE-441, CWE-269, CWE-1426]
owasp: [LLM06:2025]
attack: []
capec: [CAPEC-122]
related: [llm-prompt-injection, llm-jailbreak-and-guardrails, rag-and-vector-store-attacks, model-and-artifact-supply-chain]
---


# Agentic AI and MCP Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`AI and LLM`](../README.md) | Tier: **core** | Paired Counterpart: [`llm-input-output-guardrail-middleware-development`](../../../blue-team/security-automation-and-tool-development/llm-input-output-guardrail-middleware-development/SKILL.md)

## Mechanism and Preconditions

In an agentic system the model selects actions, so the security boundary moves from the prompt to the tool layer. The audit walks three things: what each tool can do and with whose authority, whether the model chooses the destination or only the intent, and how a tool server is trusted. An MCP server is a remote party whose tool descriptions enter the context and whose responses are data the model may act on, so both its identity and its output need treating as untrusted.

- **Destination parameters are the confused-deputy path.** A tool that accepts `recipient`, `url`, or `role` from the model lets a hijacked context choose where an action lands; the fix is to resolve those server-side.
- **Tool descriptions are prompt input.** An MCP server's tool metadata is text the model reads, so a malicious or compromised server can influence tool selection and arguments.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a tool takes a destination or authority argument **THEN** treat the tool schema as the attack surface and check whether the server resolves that value from a trusted record instead.
2. **IF** an MCP server is third-party **THEN** record its identity, the tools it exposes, and whether its descriptions can change after the client approves it.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`llm-input-output-guardrail-middleware-development`](../../../blue-team/security-automation-and-tool-development/llm-input-output-guardrail-middleware-development/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the tool inventory with authority per tool, and the trust model for each tool server — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Tool schemas with no model-supplied destination arguments, per-user delegated tokens, and MCP client validation of server identity and tool descriptions
- **First Check:** `python -c "import json; print([t['name'] for t in json.load(open('tools.json'))['tools']])"`

1. Confirm the target surface: list every tool with its side effect (read, write, transfer), the credential it uses, and which arguments the model supplies.
2. Choose the branch: authority review for tools with side effects, destination review for tools with location or recipient arguments, and server-trust review for third-party MCP connections.
3. Define the differential: run the same user request with a benign context and with a hijacked context; the differential is an action taken against a destination the user did not name.
4. Name the stop condition: every side-effecting tool either has no model-supplied destination or validates it against a server-side record, and every server's identity is pinned.
5. Prove it: the tool call with its arguments, the credential used, and the resulting external effect, so the finding shows the authority path rather than the prompt.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Tool schema exposing a destination argument` | The confused-deputy path; the model can be persuaded to name a destination the user never intended. |
| `Per-user delegated token versus a service account` | Determines whether a hijacked action is attributable and scoped to one user's authority. |
| `MCP server identity and version pinning` | A server whose descriptions can change after approval can alter tool selection later. |
| `Human approval on high-impact actions` | The control that bounds impact when the model's choice cannot be constrained structurally. |

## Worked Contrast

**Vulnerable Confused-Deputy MCP Agent (Untrusted OCR/RAG -> Direct Payout + Global Token):**

```python
# ANTI-PATTERN: Model reads untrusted OCR/RAG text and directly calls a money-moving tool
# with model-chosen recipient_iban and a shared global treasury token (zero user attribution).
@mcp.tool()
def execute_ach_payout(recipient_iban: str, amount_usd: float) -> dict:
    return treasury_api.send_wire(GLOBAL_TREASURY_TOKEN, recipient_iban, amount_usd)
```

**Hardened Capability-Split Architecture (Quarantined Extractor + Deterministic Policy + HITL):**

```python
# 1. LLM can only DRAFT a pending request referencing a pre-vetted vendor_id (NEVER raw IBAN!).
# 2. Execution requires per-user OBO token, deterministic PO/cap checks, and human dual-approval.
@mcp.tool()
def propose_invoice_payment(vendor_id: str, invoice_id: str, amount_cents: int, ctx: UserContext) -> dict:
    vendor = vendor_master.get_verified(vendor_id)  # IBAN resolved server-side from master DB
    po = erp.get_open_po(vendor_id, invoice_id)
    if po is None or amount_cents <= 0 or amount_cents > po.remaining_cents:
        raise PermissionError("Deterministic policy check failed: PO mismatch")
    return approval_queue.create_pending(
        requester=ctx.user_sub, vendor_id=vendor_id, iban=vendor.on_file_iban,
        amount_cents=amount_cents, requires_dual_human_approval=True,
    )
```

**Why this matters:** Never mount irreversible side-effect tools with free-form destination arguments (`recipient_iban`, `sql`, `shell_cmd`) or global service-account credentials on an LLM reading untrusted OCR/RAG inputs (`CWE-441` / `OWASP LLM06:2025`).

## When It Is NOT This Issue

- **Read-only tool behind an authenticated user.** A retrieval tool with the caller's own scopes does not create a confused deputy.
- **Tool that validates its argument against a server-side record.** The model supplies an id, not a destination; the resolve step is the control.
- **Approved MCP server with pinned descriptions.** Third-party is not automatically untrusted; the question is whether the client pins identity and version.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `agentic-ai-and-mcp-security` based solely on surface keywords (`tool permission`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `agentic-ai-and-mcp-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: agentic-ai-and-mcp-security
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-441, CWE-269, CWE-1426`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`llm-input-output-guardrail-middleware-development`](../../../blue-team/security-automation-and-tool-development/llm-input-output-guardrail-middleware-development/SKILL.md) - Blue Detection/Defense Counterpart
- [`llm-prompt-injection`](../llm-prompt-injection/SKILL.md) - AI and LLM (flagship)
- [`llm-jailbreak-and-guardrails`](../llm-jailbreak-and-guardrails/SKILL.md) - AI and LLM (core)
- [`rag-and-vector-store-attacks`](../rag-and-vector-store-attacks/SKILL.md) - AI and LLM (core)
- [`model-and-artifact-supply-chain`](../model-and-artifact-supply-chain/SKILL.md) - AI and LLM (leaf)
- [`ml-adversarial-and-data-poisoning`](../ml-adversarial-and-data-poisoning/SKILL.md) - AI and LLM (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `agentic-ai-and-mcp-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-441, CWE-269, CWE-1426`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/gh_advisories (3), CYBER_CPT/hacktricks (2), CYBER_CPT/owasp_genai (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
