---
name: oracle-and-price-manipulation
description: "Manipulates price oracles and derived accounting: spot price abuse, TWAP manipulation, stale oracle conditions and decimal scaling errors. Use when protocol value depends on an external price feed."
family: blockchain
tier: core
triggers: ["oracle manipulation", "price manipulation", "twap attack", "spot price"]
cwe: [CWE-682]
owasp: []
attack: []
capec: [CAPEC-442]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Oracle and Price Manipulation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Any protocol value derived from a market price is only as trustworthy as the price source's manipulation cost. The audit work is to identify every price input, determine how an attacker could move it within the protocol's decision window, and check the three properties that make a feed usable: freshness, deviation bounds, and a manipulation cost above the profit available.

- **Staleness is a silent failure.** A feed that stops updating returns the last answer forever; without a `updatedAt` check the protocol prices assets against an arbitrarily old number.
- **Decimals are a correctness bug, not a cosmetic one.** A feed with 8 decimals consumed as 18 scales every value by 10^10.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the price comes from a pool **THEN** the manipulation cost is the pool's liquidity, which for a small pool may be below the profit from one borrow.
2. **IF** the price comes from an aggregator **THEN** check `updatedAt`, the deviation threshold, and the fallback path when the answer is stale or negative.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — every price input, its update mechanism, and the protocol decision that consumes it — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Chainlink-style aggregator reads with `latestRoundData`, staleness and deviation checks, and a fallback path; Foundry fork tests for the consumption path
- **First Check:** `cast call $FEED 'latestRoundData()(uint80,int256,uint256,uint256,uint80)' --rpc-url $RPC`

1. Confirm the target surface: list every function that reads a price and the decision it feeds (borrow limit, liquidation threshold, swap quote).
2. Choose the branch: aggregator review for freshness and deviation, pool-based review for manipulation cost, and TWAP review for window length against the decision cadence.
3. Define the differential: move the price within its allowed bounds and recompute the decision; a decision that changes materially for a movement the source permits is the finding.
4. Name the stop condition: every price input has a staleness check, a deviation bound, and a documented manipulation cost, or is recorded as an open finding.
5. Prove it: a fork test showing the decision under a permitted price movement, plus the `updatedAt` value the check would have caught.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``latestRoundData` with `updatedAt` and `answeredInRound`` | The two fields that detect a stale or incomplete round; ignoring them is the most common oracle defect. |
| `Deviation threshold on the answer` | Bounds how far a single update can move the value the protocol consumes. |
| `TWAP window versus decision cadence` | A window shorter than the decision interval is manipulable; the comparison is the check. |
| `Fallback behaviour on a stale or negative answer` | A revert is safer than consuming an invalid price; a silent default is a finding. |

## Worked Contrast

**Price Consumed Without Freshness or Sign Checks:**

```solidity
contract Lending {
    AggregatorV3Interface feed;

    function collateralValue(uint256 amount) public view returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        // BUG: no updatedAt check, no positive check, no decimals normalisation
        return amount * uint256(answer) / 1e8;
    }
}
```

**Freshness, Positivity and Decimals Enforced:**

```solidity
contract Lending {
    AggregatorV3Interface feed;
    uint256 constant MAX_STALENESS = 3600;

    function collateralValue(uint256 amount) public view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answer > 0, "non-positive answer");
        require(updatedAt != 0 && block.timestamp - updatedAt <= MAX_STALENESS, "stale price");
        require(answeredInRound >= roundId, "incomplete round");
        uint256 scaled = uint256(answer) * 1e10; // 8 -> 18 decimals, explicit
        return amount * scaled / 1e18;
    }
}
```

**Why this matters:** Without the `updatedAt` check the protocol happily prices against a feed that stopped updating, and without the positivity check a negative answer becomes an enormous unsigned value; both produce a borrow limit unrelated to the market. Checking the round, the age, and the sign, and scaling decimals explicitly, makes the consumed value a bounded and current number.

## When It Is NOT This Issue

- **Feed with a documented heartbeat inside the protocol's tolerance.** A 24-hour heartbeat with a 1-hour staleness check is a real mismatch; a matching pair is not a finding.
- **Admin-settable fallback oracle.** A trusted setter is a centralisation assumption; only report it as a manipulation path if an unprivileged actor can trigger it.
- **Deviation on a low-liquidity asset.** A wide deviation threshold on an illiquid asset is a design trade-off, not automatically a defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `oracle-and-price-manipulation` based solely on surface keywords (`spot price`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `oracle-and-price-manipulation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: oracle-and-price-manipulation
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `oracle-and-price-manipulation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/go_exploitdb (3), hackerone_disclosed_reports (2), CYBER_CPT/ctf_search (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
