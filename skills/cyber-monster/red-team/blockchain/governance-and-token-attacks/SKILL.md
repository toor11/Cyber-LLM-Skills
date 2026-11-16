---
name: governance-and-token-attacks
description: "Attacks governance and token mechanics: vote buying and flash-loan voting, proposal execution gaps, token accounting abuse and delegation flaws. Use when a protocol has on-chain governance or reward tokens."
family: blockchain
tier: leaf
triggers: ["governance attack", "vote manipulation", "token abuse", "proposal exploit"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-442]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Governance and Token Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Governance and token mechanics as an attack surface: proposal thresholds and quorum, vote weight measurement and delegation, timelock delays, and reward accounting per share. The audit question is who can acquire decisive influence, at what cost, and within what delay — and whether rewards can be farmed without bearing the risk they are meant to compensate.

- **Measure the cost of a decisive vote.** Threshold times token price plus timelock duration is the attacker's budget; a protocol whose parameter changes are worth more than that cost is capture-prone.
- **Rewards per share need a checkpoint.** A reward calculated from a live balance lets a position be created just before distribution and removed just after.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** voting weight is read at execution **THEN** treat the proposal as capturable with temporary capital and check for a snapshot.
2. **IF** rewards accrue per block **THEN** check whether a deposit in the same block as a distribution captures accrued rewards without bearing the elapsed risk.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the voting mechanism, the timelock, and the reward accrual formula — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Foundry tests for proposal lifecycle and reward accrual, with checkpoint reads at specific blocks
- **First Check:** `forge test --match-test testGovernanceCapture -vvv`

1. Confirm the target surface: the threshold, quorum, voting unit, snapshot rule, timelock, and the set of actions a successful proposal can take.
2. Choose the branch: capture analysis when the threshold is buyable, timelock analysis when the delay is short relative to the value at risk, and reward analysis when accrual is per-block.
3. Define the differential: compute the value a proposal can move and compare it with the cost of acquiring the threshold; the differential is the attacker's margin.
4. Name the stop condition: every proposal action whose value exceeds the capture cost flagged, and every reward path with a same-block deposit test.
5. Prove it: the cost calculation with its inputs (token price, threshold, timelock), and a test showing a same-block deposit captures rewards it did not earn.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Threshold times price as capture cost` | The economic measure of governance security; compare it to the value a proposal can move. |
| `Timelock duration against value at risk` | A short delay with a large treasury is a margin for the attacker rather than a safety control. |
| `Snapshot block for vote weight` | Denies temporary capital a vote; its absence is the primary governance finding. |
| `Reward accrual checkpoint` | Prevents a same-block deposit from capturing rewards accrued before it existed. |

## Worked Contrast

**Execution-Weighted Votes and Live-Balance Rewards:**

```solidity
contract Gov {
    IERC20 token;
    mapping(uint256 => uint256) public votes;
    mapping(address => uint256) public rewardDebt;

    function vote(uint256 id) external {
        votes[id] += token.balanceOf(msg.sender); // BUG: live balance at execution
    }

    function claim() external {
        uint256 owed = token.balanceOf(msg.sender) * accPerShare; // BUG: live balance, no checkpoint
        token.transfer(msg.sender, owed);
    }
}
```

**Snapshot Voting With a Checkpointed Reward Index:**

```solidity
contract Gov {
    IERC20 token;
    mapping(uint256 => uint256) public votes;
    mapping(uint256 => uint256) public snapshotBlock;
    mapping(address => uint256) public rewardDebt;
    uint256 public accPerShare;

    function propose(uint256 id) external {
        snapshotBlock[id] = block.number;
    }

    function vote(uint256 id) external {
        votes[id] += token.balanceOfAt(msg.sender, snapshotBlock[id]);
    }

    function deposit(uint256 amount) external {
        _settle(msg.sender);
        token.transferFrom(msg.sender, address(this), amount);
        rewardDebt[msg.sender] = amount * accPerShare / 1e18;
    }
}
```

**Why this matters:** Voting from a live balance lets borrowed tokens decide a proposal and rewards from a live balance let a same-block deposit claim accrual it never funded. Snapshotting the vote weight at proposal creation and checkpointing rewards through an index with a per-account debt settles both: weight reflects held history, and a deposit starts earning only from the moment it exists.

## When It Is NOT This Issue

- **Threshold buyable but timelock long.** Capture needs the position held through the delay, which changes the economics; compute the full cost before reporting.
- **Reward index without a deposit event.** A protocol that distributes to a fixed set at a fixed time has no same-block farming path.
- **Delegate concentration by design.** A delegated representative holding a large share is a governance design choice to document.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `governance-and-token-attacks` based solely on surface keywords (`flash vote`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `governance-and-token-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: governance-and-token-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `governance-and-token-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (6), CYBER_CPT/sigmahq (1), CYBER_CPT/github_security_md (1), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
