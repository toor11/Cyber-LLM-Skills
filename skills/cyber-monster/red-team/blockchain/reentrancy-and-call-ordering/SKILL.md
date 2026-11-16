---
name: reentrancy-and-call-ordering
description: "Exploits reentrancy and unsafe external call ordering: single-function and cross-function reentrancy, read-only reentrancy and callback manipulation. Use when reviewing contracts making external calls before state updates."
family: blockchain
tier: core
triggers: ["reentrancy", "call ordering", "read only reentrancy", "cross function reentrancy"]
cwe: [CWE-367]
owasp: []
attack: []
capec: [CAPEC-26]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Reentrancy and Call Ordering - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Reentrancy is a control-flow property: a function makes an external call before finishing its own state updates, so the callee can re-enter and observe or exploit the intermediate state. Read-only reentrancy is the variant where the re-entered call only reads, but a third party (an oracle or a lending check) trusts that read. The audit question is which state is inconsistent at the moment of every external call.

- **The window is the finding, not the call.** Every external call has a moment when state is partially updated; the question is what a re-entrant caller can do in that window.
- **Guards are per-state, not per-function.** A `nonReentrant` on one function does not protect a view that another contract reads during the same transaction.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a function calls an external address before its last state write **THEN** enumerate what the callee can call back into, including views another protocol reads.
2. **IF** the protocol exposes a share price or balance via a view **THEN** check whether that view is consistent during a callback, because read-only reentrancy exploits exactly that.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an external call site and the state that is stale at that point — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Solidity with the deployment compiler, Foundry tests with a malicious receiver contract, and a `nonReentrant` guard where the pattern requires it
- **First Check:** `forge test --match-test testReentrancy -vvv`

1. Confirm the target surface: list every external call (`.call`, token transfers with hooks, and callback interfaces) and the state written before and after each one.
2. Choose the branch: classic reentrancy when the callee can call back into a state-changing function, read-only reentrancy when a view is stale, and cross-function reentrancy when two functions share state.
3. Define the differential: record the state at the moment of the callback and the state after the outer call completes; a callback that observes different values than a post-transaction reader is the window.
4. Name the stop condition: every external call either has the state consistent before it, or has a guard covering the state a callback could reach.
5. Prove it: a test with a malicious receiver that asserts the duplicate effect (double withdrawal, stale price read), not merely that re-entry is possible.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `State write after an external call` | The structural precondition; the write happens after control has already left, so a callback sees the old value. |
| `Malicious receiver contract in a test` | Demonstrates the exploit path concretely, which distinguishes a window from a finding. |
| ``nonReentrant` on the state-changing path` | Closes the classic variant; it does not close read-only reentrancy in views. |
| `View used by a third party during a callback` | The read-only variant: the view is stale, and the third party trusts it. |

## Worked Contrast

**External Call Before State Update:**

```solidity
contract Vault {
    mapping(address => uint256) public shares;

    function withdraw(uint256 amt) external {
        require(shares[msg.sender] >= amt, "insufficient");
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        shares[msg.sender] -= amt; // BUG: state updated after the external call
    }

    function pricePerShare() external view returns (uint256) {
        return address(this).balance / totalShares; // stale during a callback
    }
}
```

**CEI Ordering With a Guard and a Consistent View:**

```solidity
contract Vault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "reentrant");
        _locked = 2;
        _;
        _locked = 1;
    }

    function withdraw(uint256 amt) external nonReentrant {
        require(shares[msg.sender] >= amt, "insufficient");
        shares[msg.sender] -= amt;
        totalShares -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }
}
```

**Why this matters:** Writing the balance after the call lets the receiver re-enter and withdraw again against the same, still-unreduced balance, and a price view computed from the live balance is stale for the whole window. Updating state before the call and guarding the entry point removes the window, and a view derived from accounted state rather than the live balance is consistent whenever a third party reads it.

## When It Is NOT This Issue

- **Re-entry that cannot do anything.** A callback that only emits an event is not a finding; the test must show a duplicated effect.
- **Receiving contract that reverts on re-entry.** A revert bounds the impact; state that could be corrupted must still be documented.
- **Guarded path with an unguarded view.** The view may be the real issue; do not close the finding because the state-changing function is guarded.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `reentrancy-and-call-ordering` based solely on surface keywords (`external call`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `reentrancy-and-call-ordering` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: reentrancy-and-call-ordering
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-367`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)
- [`oracle-and-price-manipulation`](../oracle-and-price-manipulation/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `reentrancy-and-call-ordering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-367`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/osv (4), CYBER_CPT/gh_advisories (3), CYBER_CPT/expku (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
