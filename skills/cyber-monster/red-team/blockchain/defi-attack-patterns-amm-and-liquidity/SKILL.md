---
name: defi-attack-patterns-amm-and-liquidity
description: AMM and liquidity pool attacks. Covers pool accounting errors, donation attacks, first-depositor inflation and sandwich extraction. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: blockchain
tier: leaf
triggers: ["amm exploit", "liquidity pool attack", "donation attack", "first depositor"]
cwe: [CWE-682]
owasp: []
attack: []
capec: [CAPEC-442]
related: [defi-attack-patterns, defi-attack-patterns-lending-and-collateral, smart-contract-audit, evm-exploitation-and-tooling]
parent: defi-attack-patterns
---


# DEFI Attack Patterns Amm and Liquidity - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Automated market maker and liquidity-pool audit work: the pool's price is a function of its reserves, so anything that reads those reserves inherits their manipulability. The review covers the invariant the pool enforces, how liquidity shares are minted and burned, slippage and deadline parameters on swaps, and the initial-deposit path where share price can be set by the first liquidity provider.

- **The invariant is the specification.** For a constant-product pool, `x * y = k` must hold before and after every swap; a function that can break it breaks every price derived from the pool.
- **First liquidity sets the price.** An initial deposit with an extreme ratio makes later liquidity providers mint shares at an unfavourable rate, so `MINIMUM_LIQUIDITY` and a locked initial position are part of the security model.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the pool mints shares for the first deposit **THEN** check whether the initial share amount is burned to a permanent address, because an unbounded first share price is the mint-inflation path.
2. **IF** a swap takes a minimum-output parameter **THEN** check it is computed from the pre-swap reserves and not from a value the caller can set after the fact.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the pool invariant, the share minting formula, and the swap parameter validation — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Foundry fork tests at a pinned block, with the pool invariant asserted before and after each operation
- **First Check:** `forge test --match-test testPoolInvariant -vvv --fork-block-number 19000000`

1. Confirm the target surface: the reserve representation, the share total, and every function that changes either.
2. Choose the branch: invariant review for the swap math, share-mint review for the liquidity path, and slippage review for the caller-side parameters.
3. Define the differential: compute the invariant before and after a candidate operation; a result outside the pool's stated rounding tolerance is the finding.
4. Name the stop condition: every operation either preserves the invariant within a stated tolerance or is recorded as an open finding with the deviation.
5. Prove it: a fork test at a pinned block asserting the invariant after the operation, plus the reserve values used.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``reserve0 * reserve1` before and after a swap` | The pool's own invariant; a change beyond rounding is a broken pool. |
| ``MINIMUM_LIQUIDITY` burned on first mint` | Prevents a first provider from owning an arbitrarily small share supply and inflating the price. |
| ``amountOutMin` computed from pre-swap reserves` | Slippage protection that the caller cannot revise after the price moved. |
| ``deadline` compared to `block.timestamp`` | Bounds how long a signed swap can be held and executed at a worse price. |

## Worked Contrast

**Swap With No Slippage Bound or Invariant Check:**

```solidity
contract Pool {
    uint112 reserve0;
    uint112 reserve1;

    function swap(uint256 amountIn, bool zeroForOne) external {
        // BUG: no amountOutMin, no deadline, and no k check after the transfer
        uint256 amountOut = zeroForOne
            ? amountIn * reserve1 / (reserve0 + amountIn)
            : amountIn * reserve0 / (reserve1 + amountIn);
        token.transfer(msg.sender, amountOut);
    }
}
```

**Invariant Checked With Slippage and Deadline:**

```solidity
contract Pool {
    uint112 reserve0;
    uint112 reserve1;

    function swap(uint256 amountIn, uint256 amountOutMin, uint256 deadline, bool zeroForOne) external {
        require(block.timestamp <= deadline, "expired");
        uint256 amountOut = zeroForOne
            ? amountIn * reserve1 / (reserve0 + amountIn)
            : amountIn * reserve0 / (reserve1 + amountIn);
        require(amountOut >= amountOutMin, "slippage");
        token.transfer(msg.sender, amountOut);
        uint256 kBefore = uint256(reserve0) * reserve1;
        uint256 kAfter = uint256(reserve0 + amountIn) * uint256(reserve1 - amountOut);
        require(kAfter >= kBefore, "k"); // invariant preserved within rounding
    }
}
```

**Why this matters:** A swap with no minimum output lets a sandwich take any amount the pool will give, and with no `k` check a rounding error in the output formula silently leaks value from the pool on every trade. Asserting the minimum output the caller signed for, bounding the deadline, and checking the product after the trade keeps both the caller and the pool's own invariant protected.

## When It Is NOT This Issue

- **Rounding of one wei in the invariant.** Integer division loses precision; a `k` that is slightly lower within a documented tolerance is expected.
- **Sandwich on a user who set no slippage.** The missing parameter is the caller's omission; the pool is behaving as designed.
- **Fee-on-transfer token in a pool.** The pool may not support such tokens by design; check the documented token list before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `defi-attack-patterns-amm-and-liquidity` based solely on surface keywords (`donation`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `defi-attack-patterns-amm-and-liquidity` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: defi-attack-patterns-amm-and-liquidity
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-682`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`defi-attack-patterns-lending-and-collateral`](../defi-attack-patterns-lending-and-collateral/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `defi-attack-patterns-amm-and-liquidity` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/ctf_search (2), CYBER_CPT/go_exploitdb (2), CYBER_CPT/hacktricks (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
