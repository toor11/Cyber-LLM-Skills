---
name: smart-contract-audit-static-analysis-tooling
description: Smart contract static analysis tooling. Covers Slither, Mythril and Semgrep-style detector workflow, triage discipline and false-positive handling. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: blockchain
tier: leaf
triggers: ["slither", "mythril", "solidity static analysis"]
cwe: [CWE-284, CWE-682, CWE-362]
owasp: []
attack: []
capec: [CAPEC-116]
related: [smart-contract-audit, smart-contract-audit-testing-and-invariants, defi-attack-patterns, evm-exploitation-and-tooling]
parent: smart-contract-audit
---


# Smart Contract Audit Static Analysis Tooling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md)

## Mechanism and Preconditions

Running static analysers as a triage layer, then converting their output into review candidates: Slither's detector set and printers for structural facts, and lighter AST-based analysers for fast CI feedback. The engineering point is that detectors find shapes, not vulnerabilities, so every reported item needs a reachable path and a broken invariant before it becomes a finding.

- **Detector output is a queue, not a report.** Each item needs a caller, a state assumption, and a broken invariant; without those it is noise that erodes trust in the tool.
- **Printers are underused.** A function summary or inheritance graph from a printer often explains a detector hit faster than reading the contract.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the contract does not compile **THEN** fix compilation first, because Slither analyses the compiled IR and cannot run without it.
2. **IF** the project has many contracts **THEN** filter printer output to the entrypoints the audit scope names, rather than triaging the whole tree.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a compiling project, a pinned analyser version, and a scoped contract list — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`smart-contract-audit`](../smart-contract-audit/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Slither 0.11.x detectors and printers, plus an AST-based analyser for CI, run against a pinned compiler version
- **First Check:** `slither . --filter-paths 'test|script|lib' --exclude-dependencies`

1. Confirm the target surface: the compiler version, the contract list in scope, and the analyser version, since detector sets change between releases.
2. Choose the branch: full detector run for triage, a targeted printer for a structural question, or a custom detector when a project-specific pattern recurs.
3. Define the differential: for each candidate, compare the analyser's claim with the actual caller set; a finding with no external caller is a note.
4. Name the stop condition: a triaged list where each item is reachable or dismissed with a reason, not a raw detector count.
5. Prove it: the item's detector name and location, the external caller path, and the invariant that breaks, or an explicit dismissal with the reason.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``slither --print human-summary`` | Fast structural overview: entrypoints, modifiers, and inherited contracts, before reading any detector output. |
| `Detector name and location per item` | Makes triage auditable and lets a reviewer reproduce the exact hit. |
| ``--filter-paths` and `--exclude-dependencies`` | Keeps the queue to the project's own code, which is the only code the client can change. |
| `External caller path per candidate` | The distinction between a detector hit and a finding. |

## Worked Contrast

**Raw Detector Output Delivered as Findings:**

```bash
slither . > report.txt
# BUG: every detector hit pasted into the report, including library code and unreachable functions
```

**Scoped Run With Triaged Candidates:**

```bash
slither . --filter-paths 'test|script|lib' --exclude-dependencies --json out.json
slither . --print human-summary --filter-paths 'lib'
jq -r '.results.detectors[] | [.check, .impact, .elements[0].source_mapping.filename_relative] | @tsv' out.json | sort -u
```

**Why this matters:** A raw run includes dependency code the client cannot change and functions with no external caller, so the report is dominated by items nobody can act on. Scoping the run and extracting the detector name with its location produces a queue that can be triaged item by item, and the printer output gives the structural context needed to decide reachability.

## When It Is NOT This Issue

- **Finding in a dependency.** `lib/` code is upstream's to fix; report it only if the project can pin or patch it.
- **Detector hit on an unreachable function.** Internal-only functions need an external path before they are a finding.
- **Informational detector on style.** Naming and gas detectors are not security findings; keep them out of the security report.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `smart-contract-audit-static-analysis-tooling` based solely on surface keywords (`Slither`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `smart-contract-audit-static-analysis-tooling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: smart-contract-audit-static-analysis-tooling
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284, CWE-682, CWE-362`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`smart-contract-audit-testing-and-invariants`](../smart-contract-audit-testing-and-invariants/SKILL.md) - Blockchain (leaf)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `smart-contract-audit-static-analysis-tooling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-682, CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/nuclei_templates (2), CYBER_CPT/hacktricks (2), CYBER_CPT/gh_security_lab (1), CYBER_CPT/elastic_security (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
