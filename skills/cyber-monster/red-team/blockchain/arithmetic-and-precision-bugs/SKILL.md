---
name: arithmetic-and-precision-bugs
description: "Exploits arithmetic and precision defects: overflow in unchecked blocks, rounding direction, share and fee accounting drift, and decimal mismatch. Use when value calculations involve division or scaling."
family: blockchain
tier: leaf
triggers: ["solidity arithmetic", "rounding exploit", "precision loss", "unchecked overflow"]
cwe: [CWE-682]
owasp: []
attack: []
capec: [CAPEC-92]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Arithmetic and Precision Bugs - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Integer and fixed-point defects in Solidity: rounding direction in share and interest math, decimal mismatches between tokens, division before multiplication, and unchecked blocks in 0.8.x. The audit question for each calculation is which party the rounding favours and whether the accumulated error can be extracted repeatedly.

- **Rounding direction is a security property.** Every division in value math favours either the protocol or the user; an inconsistent direction is a drainable leak, not a cosmetic issue.
- **Decimal mismatches scale errors by 10^n.** A token with 6 decimals in an 18-decimal calculation is wrong by twelve orders of magnitude, which no unit test with a single token would catch.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the code divides **THEN** state which party benefits from the truncation and check that every path in the same accounting agrees.
2. **IF** an `unchecked` block contains arithmetic on a value derived from user input **THEN** check for a bound that makes the wrap impossible.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — each value calculation, the rounding it applies, and the token decimals it assumes — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Solidity 0.8.x checked arithmetic by default, explicit `Math.Rounding` in share math, and Foundry fuzz tests over decimals and magnitudes
- **First Check:** `forge test --match-test testRounding -vvv`

1. Confirm the target surface: list every division and every place decimals are assumed, and note the token set the protocol supports.
2. Choose the branch: share math for rounding direction, interest math for accumulation and compounding, and token integration for decimal normalisation.
3. Define the differential: compute the same quantity with exact rational arithmetic and with the contract's integer math; the difference and its sign are the finding.
4. Name the stop condition: every division has a stated rounding direction, and every decimal assumption is read from the token rather than hard-coded.
5. Prove it: a fuzz test over amounts and decimals showing the direction is consistent, or a concrete sequence where repeated rounding yields a measurable gain.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``Math.Rounding.Floor` versus `Ceil` at each conversion` | The direction must favour the protocol on every path, which is what makes the invariant durable. |
| ``token.decimals()` read rather than assumed` | Prevents the twelve-orders-of-magnitude class of bug on non-18-decimal tokens. |
| `Multiply before divide` | Preserves precision; dividing first truncates and the error compounds. |
| ``unchecked` with a proven bound` | Only safe when a preceding check makes wrap impossible; otherwise it is an overflow waiting for an input. |

## Worked Contrast

**Division Before Multiplication and Assumed Decimals:**

```solidity
contract Rewards {
    uint256 constant RATE = 3;

    function reward(uint256 principal, uint256 elapsed) public pure returns (uint256) {
        // BUG: divides first, truncating to zero for small principals
        return (principal / 1e18) * RATE * elapsed;
    }

    function toShares(uint256 assets, uint256 price) public pure returns (uint256) {
        // BUG: assumes 18 decimals for every token and floors
        return assets * 1e18 / price;
    }
}
```

**Multiply First, Decimal-Aware, Explicit Rounding:**

```solidity
contract Rewards {
    using Math for uint256;
    uint256 constant RATE = 3;

    function reward(uint256 principal, uint256 elapsed) public pure returns (uint256) {
        return principal * RATE * elapsed / 1e18; // multiply first, divide once
    }

    function toShares(uint256 assets, uint256 price, uint8 tokenDecimals) public pure returns (uint256) {
        uint256 scale = 10 ** (18 + tokenDecimals - 18);
        return (assets * scale).mulDiv(1e18, price, Math.Rounding.Floor); // shares down for the user
    }
}
```

**Why this matters:** Dividing by 1e18 before multiplying truncates any principal below one token to zero, so small positions earn nothing and the error is invisible in a test with large round numbers. Multiplying first and dividing once preserves precision, and making the decimal scale explicit with a stated rounding direction keeps every path consistent so repeated small operations cannot accumulate a gain.

## When It Is NOT This Issue

- **Rounding that favours the protocol consistently.** A floor on shares and a ceil on assets is correct; the finding is inconsistency, not truncation.
- **`unchecked` with a proven bound.** A loop counter bounded by a fixed array length is safe; state the bound rather than flagging the keyword.
- **Dust below the smallest unit.** A difference of one wei that cannot be withdrawn is not exploitable; show the accumulation path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `arithmetic-and-precision-bugs` based solely on surface keywords (`unchecked`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `arithmetic-and-precision-bugs` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: arithmetic-and-precision-bugs
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-682`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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
- [`reentrancy-and-call-ordering`](../reentrancy-and-call-ordering/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `arithmetic-and-precision-bugs` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/expku (4), CYBER_CPT/gh_advisories (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
