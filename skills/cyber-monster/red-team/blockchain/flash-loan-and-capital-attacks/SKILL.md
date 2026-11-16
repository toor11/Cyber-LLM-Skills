---
name: flash-loan-and-capital-attacks
description: Uses flash loans and atomic capital to exploit assumptions about available liquidity, governance snapshots and collateral timing. Use when a protocol assumes capital is expensive or state is stable within a transaction.
family: blockchain
tier: core
triggers: ["flash loan exploit", "capital assumption", "atomic attack", "governance flash loan"]
cwe: [CWE-362]
owasp: []
attack: []
capec: [CAPEC-442]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Flash Loan and Capital Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Flash loans remove the assumption that an attacker has capital for one transaction. The audit question is which protocol decisions assume the caller's capital is bounded — collateral checks, governance thresholds, reward snapshots, and liquidation eligibility — and what happens when those decisions are made and unmade inside one transaction.

- **Capital is free for one transaction.** Any control whose safety depends on the attacker's balance is decorative; evaluate every check as if the caller could hold any amount momentarily.
- **Snapshot timing is the lever.** A reward or vote weighted by a balance at a moment the attacker controls is manipulable; a time-weighted average is not.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a decision uses a balance read in the current block **THEN** ask what the attacker can do with unlimited temporary capital before concluding the check is sound.
2. **IF** governance weight is measured at proposal execution **THEN** a flash-borrowed position can vote; check for a snapshot or a lock.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the protocol decisions that read caller capital, and the block at which each is evaluated — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Foundry fork tests with a flash-loan mock or a real lender, expressing the whole attack as one transaction at a pinned block
- **First Check:** `forge test --match-test testFlashCapital -vvv --fork-url $RPC`

1. Confirm the target surface: list every decision that reads a balance, a share price, or a voting weight, and note whether the read is instantaneous or time-weighted.
2. Choose the branch: collateral timing for lending, snapshot weighting for rewards and governance, and liquidation eligibility when the trigger depends on a manipulable price.
3. Define the differential: the same decision evaluated with the attacker's capital before and after a temporary position; a decision that changes materially and reverts the capital afterwards is the finding.
4. Name the stop condition: every capital-dependent decision is either time-weighted, snapshot-based, or recorded as an open exposure with its profit path.
5. Prove it: a fork test that borrows, acts, and repays within one transaction, printing the resulting profit and the invariant that broke.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Balance read at execution time` | The precondition for a flash-capital attack; the read has no memory of how the balance came to exist. |
| `Time-weighted or snapshot balance` | The mitigation: the decision depends on history the attacker cannot rewrite in one transaction. |
| `Liquidation triggered by a manipulable price` | A liquidator can move the price to make a healthy position eligible. |
| `Vote weight at execution rather than at snapshot` | Governance capture with borrowed capital, which costs only the flash fee. |

## Worked Contrast

**Collateral and Vote Weight From Instantaneous Balances:**

```solidity
contract Market {
    IERC20 public token;
    mapping(address => uint256) public deposits;

    function borrow(uint256 amount) external {
        // BUG: collateral measured from the current balance, so flash-borrowed tokens count
        require(token.balanceOf(msg.sender) * 2 >= amount, "undercollateralised");
        token.transfer(msg.sender, amount);
    }

    function vote(uint256 proposal) external {
        // BUG: weight from the current balance, so borrowed tokens vote
        weight[proposal] += token.balanceOf(msg.sender);
    }
}
```

**Snapshotted Collateral With a Locked Position:**

```solidity
contract Market {
    IERC20 public token;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lockedUntil;

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        lockedUntil[msg.sender] = block.timestamp + 1 days;
    }

    function borrow(uint256 amount) external {
        require(block.timestamp > lockedUntil[msg.sender], "position locked");
        require(deposits[msg.sender] * 2 >= amount, "undercollateralised");
        token.transfer(msg.sender, amount);
    }

    function vote(uint256 proposal, uint256 weight) external {
        require(deposits[msg.sender] >= weight, "weight above deposit");
        votes[proposal][msg.sender] = weight;
    }
}
```

**Why this matters:** Reading a live balance means a flash loan makes the caller arbitrarily collateralised and arbitrarily influential for the duration of one transaction, at a cost of only the loan fee. Requiring a deposited, locked position and measuring weight against that deposit removes the free-capital assumption, because the capital has to stay at risk for the lock period.

## When It Is NOT This Issue

- **Flash loan used for a legitimate arbitrage.** Profit from pool imbalance is not a protocol loss; the finding needs another user's balance to change.
- **Snapshot taken at proposal creation.** A common and effective mitigation; verify the snapshot block rather than assuming execution-time weighting.
- **Temporary capital with a lock.** A deposit requirement with a withdrawal delay already denies the free-capital advantage.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `flash-loan-and-capital-attacks` based solely on surface keywords (`flash loan`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `flash-loan-and-capital-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: flash-loan-and-capital-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-362`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `flash-loan-and-capital-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/nuclei_templates (4), CYBER_CPT/gh_advisories (2), CYBER_CPT/sigmahq (1), CYBER_CPT/atomic_red_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
