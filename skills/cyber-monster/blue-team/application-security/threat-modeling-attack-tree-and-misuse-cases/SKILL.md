---
name: threat-modeling-attack-tree-and-misuse-cases
description: Attack trees and misuse cases. Covers building attack trees and misuse cases to capture realistic adversary goals and paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: application-security
tier: leaf
triggers: ["attack tree", "misuse case", "adversary goal"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-modeling, threat-modeling-stride-analysis, secure-code-review, secure-sdlc-and-security-requirements]
parent: threat-modeling
---

# Threat Modeling Attack Tree and Misuse Cases - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

An attack tree starts from an adversary goal and decomposes it into the alternative and sequential steps that would achieve it, with each leaf being something you can test or control. Misuse cases do the same from the user's perspective, describing a legitimate actor doing something the system should prevent. Both are goal-driven rather than element-driven, which is why they find the multi-step paths that per-element grids miss - the ones where each individual step is authorised but the sequence is not.

- **Each leaf must be an observable action or condition**, not a category; 'phishing' is a node, 'reset token predictable from timestamp' is a leaf.
- The root is a goal stated from the adversary's side ('read another tenant's invoices'), which forces the tree to be about a consequence rather than a technique.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is coverage of a design element by element **THEN** use `threat-modeling-stride-analysis`; that grid answers 'what can go wrong here' rather than 'how is this goal reached'.
2. **IF** a leaf becomes a test **THEN** pass it to `purple-teaming-and-adversary-emulation-technique-selection` with the observable it should produce.
3. **IF** the goal involves a named adversary group **THEN** start from `adversary-tracking-and-attribution` for the actor's TTPs instead of inventing the tree.
4. **IF** the target narrows to `threat-modeling` **THEN** open [`threat-modeling`](../threat-modeling/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`threat-modeling`](../threat-modeling/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **State the root goal as a consequence.** One sentence, adversary-subject, naming the asset and the harm. A vague root produces a tree of techniques; a consequence root produces paths you can break.
2. **Decompose with AND/OR structure explicitly.** OR nodes are alternatives (any one suffices), AND nodes are steps that must all succeed. Mark them, because the cheapest mitigation is usually a single AND child.
3. **Stop expanding at testable leaves.** A leaf is testable when you can name the request, condition, or configuration that would achieve it and the observable it produces.
4. **Define the baseline-vs-probe differential per path.** Baseline: the legitimate sequence. Probe: the path with one step substituted. The path is credible when a defence you can name would break it, and the differential shows whether that defence is present.
5. **State the stop condition and the proof.** Stop when every root has at least one complete path with a named break point, and every leaf has an owner; proof is the tree plus the break-point locations, not the leaf count.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| AND path where one step requires an unaudited admin action | Proves the cheapest mitigation is auditing that step, which converts the whole path into a detection. |
| OR path with three alternatives, two sharing one control | Proves the control is the high-leverage fix; attacking leaves individually misses it. |
| Misuse case where a legitimate user's sequence exceeds their authority | Proves a business-logic gap that no single-request authorisation check catches. |
| Leaf that requires a configuration not present in production | Proves the path is theoretical for this deployment; record the config condition as the break point. |

## Worked Contrast

**Attack tree of techniques (no consequence, leaves untestable):**

```text
Goal: compromise the app
- Phishing
- Exploit web vulnerability
  - SQL injection
  - XSS
- Credential stuffing
Mitigation: train users, patch systems
```

**Attack tree from a consequence, with AND/OR structure and break points:**

```text
GOAL (OR): read invoices belonging to another tenant
|- OR  obtain a session for another tenant's user
|   |- AND guess credentials + no lockout             BREAK: lockout at auth/login.py:52 (5/15m)
|   +- AND steal reset token + token reusable         BREAK: single-use consume at auth/reset.py:31
+- OR  use own session against another tenant's object
    |- AND know object id + lookup unscoped           BREAK: tenant predicate in InvoiceRepo.get
    +- AND batch endpoint skips per-item scope        BREAK: per-item filter (missing today)
Leaf test: POST /v1/invoices/batch with foreign ids -> expect 404 per item
```

**Why this matters:** The first tree lists techniques and ends in advice nobody can verify. The second starts from the harm, marks the AND steps, and names the control that breaks each path at a file - so the one missing break point is visible as the finding, and the tree's leaves are already tests.

## When It Is NOT This Issue

- **Tree that restates the STRIDE grid.** If every leaf is 'spoofing on element X', it is a grid in disguise and misses sequences.
- **Path requiring an already-compromised host.** Post-compromise escalation belongs to a separate tree whose root is host access; mixing them makes the initial-access defences look ineffective.
- **Leaf that is a tool name.** 'Uses sqlmap' describes no condition; the leaf is the missing parameterisation it would find.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `threat-modeling-attack-tree-and-misuse-cases` based solely on surface keywords (`attack tree`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-modeling-attack-tree-and-misuse-cases` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: threat-modeling-attack-tree-and-misuse-cases
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`threat-modeling-stride-analysis`](../threat-modeling-stride-analysis/SKILL.md) - Application Security (leaf)
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-modeling-attack-tree-and-misuse-cases` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 2 |
| Top sources | SecEval/owasp_wstg (2), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | multi-dataset corpus-grounded |
