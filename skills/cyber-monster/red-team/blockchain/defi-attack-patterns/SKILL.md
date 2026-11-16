---
name: defi-attack-patterns
description: "Exploits DeFi protocol logic: flash loan manipulation, oracle manipulation, price and share accounting errors, MEV extraction and liquidation abuse. Use when the target is a lending, AMM, vault or derivatives protocol."
family: blockchain
tier: flagship
triggers: ["defi exploit", "flash loan attack", "oracle manipulation", "amm exploit", "mev"]
cwe: [CWE-682]
owasp: []
attack: []
capec: [CAPEC-442]
related: [defi-attack-patterns-lending-and-collateral, defi-attack-patterns-amm-and-liquidity, smart-contract-audit, evm-exploitation-and-tooling]
---


# DEFI Attack Patterns - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **flagship** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

The attack surface of a DeFi protocol is the gap between what its accounting assumes and what an attacker can do inside a single transaction: borrowed capital, donated tokens, manipulated spot prices, and reordered trades. Auditing it means asking, for each price or balance the protocol trusts, whether an unprivileged actor can move it within one block and profit from the resulting state.

- **Flash capital removes the size constraint.** Any check whose safety depends on the attacker not having funds is not a check; assume unlimited capital for one transaction.
- **Donations and rebases break balance-based accounting.** `balanceOf` includes tokens sent directly, so any share price derived from it is manipulable.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target resolves to `defi-attack-patterns-lending-and-collateral` **THEN** switch to [`defi-attack-patterns-lending-and-collateral`](../defi-attack-patterns-lending-and-collateral/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
2. **IF** the target resolves to `defi-attack-patterns-amm-and-liquidity` **THEN** switch to [`defi-attack-patterns-amm-and-liquidity`](../defi-attack-patterns-amm-and-liquidity/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
3. **IF** a price comes from a pool's spot reserves **THEN** treat it as manipulable in the same transaction and look for a TWAP or an external feed instead.
4. **IF** share price is `totalAssets() / totalSupply()` with `totalAssets()` from `balanceOf` **THEN** the first-depositor and donation paths are the priority.
5. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
6. **IF** the input cannot establish the precondition this skill needs — a protocol with at least one price or balance input, and the set of actions an unprivileged address can take in one transaction — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `defi-attack-patterns-lending-and-collateral` | [`defi-attack-patterns-lending-and-collateral`](../defi-attack-patterns-lending-and-collateral/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `defi-attack-patterns-amm-and-liquidity` | [`defi-attack-patterns-amm-and-liquidity`](../defi-attack-patterns-amm-and-liquidity/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Foundry fork tests against the deployment block, with the attack sequence expressed as one transaction; invariant tests for the accounting property
- **First Check:** `forge test --match-test testFlashLoanSequence -vvv --fork-url $RPC`

1. Confirm the target surface: list every external input to the protocol's accounting — pool reserves, oracle answers, token balances, and the caller's own deposits.
2. Choose the branch: price manipulation when a value is derived from a pool, donation or inflation when a share price is derived from a balance, and ordering when profit depends on transaction position.
3. Define the differential: compute the protocol's state before and after one atomic sequence, and require the attacker's profit to come from other users' balances rather than from the attacker's own capital.
4. Name the stop condition: one atomic sequence that breaks an accounting invariant, or a demonstration that every input is either time-weighted or bounded.
5. Prove it: a fork test at a pinned block that shows the profit and the invariant break, plus the specific input that allowed it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Pool spot reserves as a price source` | Manipulable within one transaction by anyone with flash capital, so any value derived from it is attacker-controlled. |
| ``totalAssets()` from `balanceOf`` | Includes donated tokens, which inflates share price and enables first-depositor and donation attacks. |
| `Single-block profit from another user's balance` | The distinguishing feature of a real attack versus a arbitrage that profits from mispricing alone. |
| `Transaction ordering dependence` | Profit that exists only for the first or last transaction in a block, which is a sandwich rather than a protocol bug. |

## Worked Contrast

**Spot Price and Donation-Sensitive Accounting:**

```solidity
contract Lending {
    IUniswapV2Pair pair;
    mapping(address => uint256) collateral;

    function collateralValue(address user) public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return collateral[user] * r0 / r1; // BUG: spot reserves, movable in the same transaction
    }

    function totalAssets() public view returns (uint256) {
        return token.balanceOf(address(this)); // BUG: donations inflate this
    }
}
```

**Time-Weighted Price and Internal Accounting:**

```solidity
contract Lending {
    IUniswapV3Pool pool;
    uint32 constant WINDOW = 1800;
    mapping(address => uint256) collateral;
    uint256 private _trackedAssets;

    function collateralValue(address user) public view returns (uint256) {
        (uint160 sqrtP, , , , , , ) = pool.slot0();
        uint256 twap = _quoteFromSqrtPrice(sqrtP, WINDOW); // bounded, time-weighted
        return collateral[user] * twap / 1e18;
    }

    function totalAssets() public view returns (uint256) {
        return _trackedAssets; // mutated only by deposit and withdraw
    }
}
```

**Why this matters:** Reading spot reserves lets an attacker move the price in the same transaction that uses it, so collateral value is whatever they choose; deriving share price from `balanceOf` lets a direct transfer inflate every share. A time-weighted price with a stated window and internal accounting that only deposit and withdraw can change remove both levers, which is what makes the accounting invariant hold across an arbitrary sequence.

## When It Is NOT This Issue

- **Arbitrage against a mispriced pool.** Profit that comes from the pool's own imbalance is not a protocol loss; check whether any user balance changed.
- **Sandwich on a user's swap.** Ordering profit is an MEV issue with its own mitigations, not a protocol accounting bug.
- **Admin-settable oracle.** A trusted setter is a centralisation assumption to document, not an atomic manipulation path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `defi-attack-patterns` based solely on surface keywords (`flash loan`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `defi-attack-patterns` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: defi-attack-patterns
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-682`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`defi-attack-patterns-lending-and-collateral`](../defi-attack-patterns-lending-and-collateral/SKILL.md) - Blockchain (leaf)
- [`defi-attack-patterns-amm-and-liquidity`](../defi-attack-patterns-amm-and-liquidity/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `defi-attack-patterns` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/github_security_md (6), CYBER_CPT/ctftime (2), CYBER_CPT/ctf_wiki (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
