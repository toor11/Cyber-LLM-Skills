---
name: smart-contract-audit
description: "Audits smart contracts for security defects: access control, arithmetic, external call ordering and upgrade patterns, using static review plus test harnesses. Use when reviewing Solidity or Vyper code."
family: blockchain
tier: core
triggers: ["smart contract audit", "solidity audit", "contract review", "defi audit"]
cwe: [CWE-284, CWE-682, CWE-362]
owasp: []
attack: []
capec: [CAPEC-116]
related: [smart-contract-audit-static-analysis-tooling, smart-contract-audit-testing-and-invariants, defi-attack-patterns, evm-exploitation-and-tooling]
---


# Smart Contract Audit - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md)

## Mechanism and Preconditions

A full-scope audit of a Solidity system: inventory every external entrypoint and the value it controls, map the state each one may change, then test the invariants that must hold after any sequence of calls — solvency, share accounting, access boundaries, and upgrade authority. The audit is ordered by value at risk: fund-moving paths first, then access control, then everything reachable only through an existing privilege.

- **Entrypoints first, findings second.** An audit that starts from a tool's output reviews whatever the tool knows; starting from the entrypoint list reviews what the protocol actually exposes.
- **Every invariant names a quantity.** 'Accounting is correct' is untestable; 'sum of user balances never exceeds the token balance held by the contract' is a property a harness can falsify.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target resolves to `smart-contract-audit-static-analysis-tooling` **THEN** switch to [`smart-contract-audit-static-analysis-tooling`](../smart-contract-audit-static-analysis-tooling/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
2. **IF** the target resolves to `smart-contract-audit-testing-and-invariants` **THEN** switch to [`smart-contract-audit-testing-and-invariants`](../smart-contract-audit-testing-and-invariants/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
3. **IF** a function moves funds **THEN** establish its authorisation path and the exact state it mutates before reading anything else in the file.
4. **IF** the protocol is upgradeable **THEN** audit the initialiser and the upgrade authority before the logic, because a wrong initialiser makes the logic irrelevant.
5. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md).
6. **IF** the input cannot establish the precondition this skill needs — a deployed or deployable system, an entrypoint inventory, and at least one quantity invariant — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `smart-contract-audit-static-analysis-tooling` | [`smart-contract-audit-static-analysis-tooling`](../smart-contract-audit-static-analysis-tooling/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `smart-contract-audit-testing-and-invariants` | [`smart-contract-audit-testing-and-invariants`](../smart-contract-audit-testing-and-invariants/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Solidity compiler version pinned to the deployment, Slither for triage, and a Foundry fork test for each candidate finding
- **First Check:** `forge build && slither . --filter-paths 'test|script'`

1. Confirm the target surface: list every external and public function, classify each as fund-moving, privileged, or read-only, and record the compiler version from the build configuration.
2. Choose the branch: value-flow review for anything touching balances, access review for privileged functions, and upgrade review for proxies and initialisers.
3. Define the differential: for each candidate finding, write the state before and after the call sequence and name the invariant that breaks; a candidate without a broken invariant is a code-quality note.
4. Name the stop condition: every fund-moving path either has a test that demonstrates the invariant holds, or is recorded as an open finding with the missing check.
5. Prove it: a failing Foundry test that reproduces the broken invariant on a fork, or an explicit statement that the invariant holds and the test that shows it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `External entrypoint inventory` | Defines the review's boundary; every later finding must attach to one of these functions. |
| `State variable touched per entrypoint` | Shows which functions can conflict, which is where reentrancy and accounting bugs live. |
| `Invariant as a quantity comparison` | The falsifiable form of a security property, and the only kind a harness can test. |
| `Upgrade authority and initialiser guard` | Determines whether a logic bug is reachable before or after deployment, and who can change it. |

## Worked Contrast

**Review Driven by Tool Output Only:**

```solidity
contract Bank {
    mapping(address => uint256) public balances;
    // Tool reports nothing here: no reentrancy, no unchecked call, no delegatecall.
    function withdraw(uint256 amt) external {
        require(balances[msg.sender] >= amt);
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    }
    function sweep() external {
        payable(owner()).transfer(address(this).balance); // BUG: no owner check on a sweep
    }
}
```

**Entrypoint Review With Named Invariants:**

```solidity
contract Bank {
    mapping(address => uint256) public balances;
    address public immutable owner;

    constructor(address o) { owner = o; }

    // Invariant: sum(balances) <= address(this).balance at every block boundary.
    function withdraw(uint256 amt) external nonReentrant {
        require(balances[msg.sender] >= amt, "insufficient");
        balances[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }

    // Privileged entrypoint: authorisation checked before the transfer.
    function sweep(address to) external {
        require(msg.sender == owner, "not owner");
        payable(to).transfer(address(this).balance);
    }
}
```

**Why this matters:** The first contract has no pattern a detector recognises, yet `sweep` lets any caller drain the balance because the only check is a comment. Starting from the entrypoint inventory forces the question 'who may call this and what does it move', which finds the missing authorisation that no pattern rule expresses.

## When It Is NOT This Issue

- **Detector output without a reachable path.** A Slither finding on a function with no external caller is a note, not a vulnerability.
- **Admin-only path treated as unauthenticated.** Many findings assume an attacker who already holds the owner key; state the precondition.
- **Design decision read as a bug.** A fee switch, a pause, or a privileged upgrade path is a trust assumption to document, not a defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `smart-contract-audit` based solely on surface keywords (`access control`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `smart-contract-audit` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: smart-contract-audit
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284, CWE-682, CWE-362`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`smart-contract-audit-static-analysis-tooling`](../smart-contract-audit-static-analysis-tooling/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit-testing-and-invariants`](../smart-contract-audit-testing-and-invariants/SKILL.md) - Blockchain (leaf)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `smart-contract-audit` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-682, CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 54 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (27), hackerone_disclosed_reports (11), bugbounty-hunter-v1 (4), SecEval/owasp_wstg (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
