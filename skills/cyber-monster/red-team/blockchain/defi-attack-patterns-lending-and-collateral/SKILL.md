---
name: defi-attack-patterns-lending-and-collateral
description: Lending and collateral attacks. Covers collateral valuation abuse, liquidation manipulation and bad-debt paths in lending markets. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: blockchain
tier: leaf
triggers: ["lending exploit", "collateral manipulation", "liquidation abuse"]
cwe: [CWE-682]
owasp: []
attack: []
capec: [CAPEC-442]
related: [defi-attack-patterns, defi-attack-patterns-amm-and-liquidity, smart-contract-audit, evm-exploitation-and-tooling]
parent: defi-attack-patterns
corpus_sparse: true
---


# DEFI Attack Patterns Lending and Collateral - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Lending-market audit work: collateral factors, liquidation thresholds and bonuses, interest accrual indices, and the bad-debt path when a position cannot be liquidated profitably. The characteristic failures are a collateral factor that lets a position be opened at or above the liquidation threshold, a liquidation bonus large enough to make liquidating a healthy position profitable, and an interest index that compounds in the borrower's favour.

- **The gap between collateral factor and liquidation threshold is the safety margin.** A position opened at the maximum loan-to-value has no buffer, so a one-tick price move makes it liquidatable.
- **Bad debt is a design state, not an error.** When collateral value falls below debt, the protocol must have a defined path; an undefined one means the loss lands on depositors silently.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the maximum borrow is computed from the collateral factor **THEN** compare it with the liquidation threshold, because the difference is the only buffer a borrower has.
2. **IF** liquidation pays a bonus **THEN** check it against the close factor, since a large bonus with a full close makes liquidating a marginally unhealthy position profitable and can be self-triggered.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the collateral factor, the liquidation threshold and bonus, and the interest index update rule — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

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

- **Pinned Inputs:** Foundry tests over the borrow and liquidation lifecycle with a mock price feed, plus a fork test against the deployed market
- **First Check:** `forge test --match-test testLiquidation -vvv`

1. Confirm the target surface: the collateral factor per asset, the liquidation threshold and bonus, the close factor, and the interest index formula.
2. Choose the branch: opening-position review for the LTV buffer, liquidation review for bonus and close-factor economics, and interest review for index compounding.
3. Define the differential: compute the health factor immediately after opening at the maximum borrow and after a small adverse price move; a position liquidatable within the asset's normal volatility is the finding.
4. Name the stop condition: every asset has a documented buffer between the borrow limit and the liquidation threshold, and a defined bad-debt path.
5. Prove it: a test that opens at maximum LTV, moves the price by a realistic amount, and shows whether the position becomes liquidatable.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Collateral factor below the liquidation threshold` | The buffer; equality means no buffer at all and the position is liquidatable on any adverse move. |
| `Liquidation bonus times close factor` | Determines whether liquidating a marginal position is profitable, which decides if bad debt accrues. |
| `Interest index updated on every accrual` | A stale index underprices debt and lets a borrower repay less than owed. |
| `Bad-debt path when collateral is worth less than debt` | A defined state with a loss-allocation rule; its absence hides the loss in depositor balances. |

## Worked Contrast

**Borrow Limit Equal to the Liquidation Threshold:**

```solidity
contract Market {
    uint256 constant COLLATERAL_FACTOR = 8000; // 80%
    uint256 constant LIQUIDATION_THRESHOLD = 8000; // BUG: no buffer between borrow and liquidation

    function borrow(uint256 amount) external {
        uint256 limit = collateralValue(msg.sender) * COLLATERAL_FACTOR / 10000;
        require(debt[msg.sender] + amount <= limit, "over limit");
        debt[msg.sender] += amount;
    }

    function liquidate(address user) external {
        require(healthFactor(user) < 1e18, "healthy");
        // BUG: bonus not bounded by available collateral, loss undefined
    }
}
```

**Buffered LTV With a Bounded Bonus and a Bad-Debt Path:**

```solidity
contract Market {
    uint256 constant COLLATERAL_FACTOR = 7000; // 70% borrow
    uint256 constant LIQUIDATION_THRESHOLD = 8000; // 80% liquidate
    uint256 constant BONUS_BPS = 500; // 5%

    function borrow(uint256 amount) external {
        uint256 limit = collateralValue(msg.sender) * COLLATERAL_FACTOR / 10000;
        require(debt[msg.sender] + amount <= limit, "over limit");
        debt[msg.sender] += amount;
    }

    function liquidate(address user, uint256 repayAmount) external {
        require(healthFactor(user) < 1e18, "healthy");
        uint256 seize = repayAmount * (10000 + BONUS_BPS) / 10000;
        uint256 available = collateralValue(user);
        if (seize > available) {
            seize = available; // loss is realised, not silently absorbed
            emit BadDebt(user, repayAmount - available * 10000 / (10000 + BONUS_BPS));
        }
        _seize(user, seize);
    }
}
```

**Why this matters:** With the borrow limit equal to the liquidation threshold, a position at maximum LTV is liquidatable on any adverse tick, so borrowers are liquidated for the bonus rather than for risk. Separating the two numbers creates a buffer, bounding the bonus against available collateral keeps liquidation from creating an unfunded obligation, and emitting the bad-debt event makes the loss visible instead of hiding it in depositor balances.

## When It Is NOT This Issue

- **Liquidation of a genuinely unhealthy position.** Liquidating at a threshold with a bounded bonus is the mechanism working.
- **Interest index lag of one block.** Accrual granularity is a design choice; the finding is a stale index that misprices debt materially.
- **Collateral factor set by governance per asset.** A conservative factor for a volatile asset is risk management, not a defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `defi-attack-patterns-lending-and-collateral` based solely on surface keywords (`collateral factor`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `defi-attack-patterns-lending-and-collateral` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: defi-attack-patterns-lending-and-collateral
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
- [`defi-attack-patterns-amm-and-liquidity`](../defi-attack-patterns-amm-and-liquidity/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `defi-attack-patterns-lending-and-collateral` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
