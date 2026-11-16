---
name: wallet-and-key-management-attacks-approval-and-permit-abuse
description: Token approval and permit abuse. Covers unlimited approvals, permit signature phishing and allowance drain patterns. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: blockchain
tier: leaf
triggers: ["approval drain", "permit phishing", "allowance abuse"]
cwe: [CWE-321]
owasp: []
attack: []
capec: [CAPEC-59]
related: [wallet-and-key-management-attacks, wallet-and-key-management-attacks-key-generation-weakness, smart-contract-audit, defi-attack-patterns]
parent: wallet-and-key-management-attacks
---


# Wallet and Key Management Attacks Approval and Permit Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

The approval surface: ERC-20 `approve` and `increaseAllowance` grants, ERC-721 `setApprovalForAll`, and EIP-2612 permits signed off-chain. The audit question is what standing authority exists, to whom, whether the spender can change meaning without the owner acting again, and whether a permit can be replayed or front-run.

- **A permit is a signed approval.** It carries the same risk as `approve` but arrives off-chain, so a signature over an unbounded value is an unbounded grant that never touches the chain until it is used.
- **`setApprovalForAll` is total.** One transaction grants a spender control of every token in the collection, which makes the spender's identity and mutability the entire security question.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the system asks for an unlimited approval **THEN** check whether a bounded allowance with a reset would work, and document the trust assumption if it would not.
2. **IF** a permit is verified **THEN** check the deadline is enforced against `block.timestamp` and the nonce is per-owner.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the approval inventory, the spender contracts, and the permit verification code — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** On-chain allowance and approval reads at a pinned block, EIP-2612 `permit` review, and a test asserting an expired permit reverts
- **First Check:** `cast call $TOKEN 'allowance(address,address)(uint256)' $OWNER $SPENDER --block $BLOCK --rpc-url $RPC`

1. Confirm the target surface: every approval the system requests or holds, the spender contract for each, and whether the spender is upgradeable.
2. Choose the branch: ERC-20 allowance review for amounts and reset behaviour, ERC-721 operator review for scope, and permit review for deadline and nonce enforcement.
3. Define the differential: compare the granted allowance with the amount the operation needs; a grant far above the need, with no expiry mechanism, is the finding.
4. Name the stop condition: every approval either bounded in amount, bounded in time, or explicitly documented as a trust assumption.
5. Prove it: the allowance read at a block, the spender's identity and upgradeability, and a permit test showing an expired signature reverts.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``allowance(owner, spender)` at a block` | The factual grant, independent of any interface or documentation. |
| `Spender mutability` | An approval to an upgradeable spender is authority over whatever the implementation becomes. |
| ``permit` deadline against `block.timestamp`` | The only thing that bounds a signature's usable window. |
| ``setApprovalForAll` operator identity` | Total control of a collection; the operator's identity is the whole risk. |

## Worked Contrast

**Permit Accepted With No Deadline Check:**

```solidity
contract Staking {
    function stakeWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        // BUG: deadline passed to the token but never checked here, and the value is unbounded
        IERC20Permit(address(token)).permit(msg.sender, address(this), type(uint256).max, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

**Bounded Permit With an Enforced Deadline:**

```solidity
contract Staking {
    function stakeWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "permit expired");
        IERC20Permit(address(token)).permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
    }
}
```

**Why this matters:** Submitting a permit with an unlimited value grants the contract permanent authority over the user's whole balance, and ignoring the deadline makes a signature usable indefinitely after it was signed. Approving exactly the amount being staked and rejecting an expired signature keep the grant equal to the operation and inside the window the signer intended.

## When It Is NOT This Issue

- **Unlimited approval to an immutable, audited router.** A recognised pattern; record the trust assumption rather than treating it as a defect.
- **Permit reverting on second use.** That is the nonce working as designed.
- **Operator approval for a marketplace.** Total approval to a marketplace is the standard flow; the finding is a mutable or unverified operator.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `wallet-and-key-management-attacks-approval-and-permit-abuse` based solely on surface keywords (`approve max`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wallet-and-key-management-attacks-approval-and-permit-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: wallet-and-key-management-attacks-approval-and-permit-abuse
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-321`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks-key-generation-weakness`](../wallet-and-key-management-attacks-key-generation-weakness/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wallet-and-key-management-attacks-approval-and-permit-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/go_exploitdb (6) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
