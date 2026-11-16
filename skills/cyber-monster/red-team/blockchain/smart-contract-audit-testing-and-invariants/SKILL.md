---
name: smart-contract-audit-testing-and-invariants
description: Contract testing and invariant fuzzing. Covers Foundry and Echidna testing, invariant design and property-based harnesses that find real bugs. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: blockchain
tier: leaf
triggers: ["foundry test", "echidna", "invariant fuzzing", "property testing"]
cwe: [CWE-284, CWE-682, CWE-362]
owasp: []
attack: []
capec: [CAPEC-116]
related: [smart-contract-audit, smart-contract-audit-static-analysis-tooling, defi-attack-patterns, evm-exploitation-and-tooling]
parent: smart-contract-audit
---


# Smart Contract Audit Testing and Invariants - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md)

## Mechanism and Preconditions

Encoding the audit's claims as executable tests: unit tests for specific paths, fork tests against deployed state, and stateful invariant campaigns that assert a property after arbitrary sequences. The test suite is the evidence; a finding without a failing test is a hypothesis, and an invariant without a handler that can break it is decoration.

- **The handler defines the reachable state space.** Actor count, value bounds, and available actions decide whether an invariant can fail; an unbounded handler finds arithmetic limits, not protocol bugs.
- **Fork tests pin the world.** A fork test at a stated block reproduces behaviour against real state, which is what makes a finding about a deployed protocol credible.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the property is about a quantity **THEN** write it as an invariant and give the handler the actions that could break it.
2. **IF** the protocol is deployed **THEN** fork at a specific block and quote that block with the test, because an unpinned fork changes underneath you.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a compiling project, a named property, and a handler whose actions can violate it — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`smart-contract-audit`](../smart-contract-audit/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Foundry `forge test` with `StdInvariant`, `targetContract`, `bound`, and `--fork-block-number` for fork tests
- **First Check:** `forge test --match-contract Invariant -vv`

1. Confirm the target surface: the property, the functions that can change the quantities in it, and the actors who can call them.
2. Choose the branch: unit test for a specific path, fork test for deployed behaviour, and invariant campaign for properties that must hold across sequences.
3. Define the differential: the property must hold on the unmodified deployment and fail on the candidate change; a test that fails on both is measuring something else.
4. Name the stop condition: a call depth, a run count, and a corpus directory, so any failure is reproducible.
5. Prove it: the minimal failing sequence exported from the campaign, replayed against the fork block, with the invariant named.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``targetContract(address(handler))`` | Restricts the action set, which is how actor count and bounds are enforced on the campaign. |
| ``bound(value, min, max)`` | Keeps generated values in the protocol's real domain instead of at type limits. |
| ``--fork-block-number`` | Makes a deployed-state test reproducible after the chain moves on. |
| `Exported counterexample sequence` | The finding itself; a failing invariant without the sequence cannot be reviewed. |

## Worked Contrast

**Invariant That Cannot Fail:**

```solidity
contract Props is StdInvariant, Test {
    Vault vault;
    function setUp() public { vault = new Vault(); }
    function invariant_supplyPositive() public view {
        assertGe(vault.totalSupply(), 0); // BUG: unsigned, always true
    }
}
```

**Handler-Bounded Property Over Two Quantities:**

```solidity
contract Handler is Test {
    Vault vault;
    function deposit(uint256 amt) public {
        amt = bound(amt, 1, 1e24);
        vault.deposit(amt, address(this));
    }
    function withdraw(uint256 amt) public {
        amt = bound(amt, 0, vault.balanceOf(address(this)));
        vault.withdraw(amt, address(this), address(this));
    }
}

contract Props is StdInvariant, Test {
    Vault vault;
    Handler handler;
    function setUp() public {
        vault = new Vault();
        handler = new Handler();
        targetContract(address(handler));
    }
    function invariant_assetsCoverShares() public view {
        assertGe(vault.totalAssets(), vault.totalSupply());
    }
}
```

**Why this matters:** An invariant over an unsigned value is a tautology and its green run is meaningless. Bounding a handler to real deposit and withdraw amounts and asserting a relation between two quantities gives the fuzzer a property it can actually break, and the handler's action set is what makes the reached state space relevant to the protocol.

## When It Is NOT This Issue

- **Passing invariant with no handler calls.** Check reached coverage; a campaign that never entered the handler proves nothing.
- **Failure caused by unbounded inputs.** Values above the real supply produce reverts that look like violations; bound the handler.
- **Unpinned fork test.** The result changes as the chain advances, so it cannot be a regression test.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `smart-contract-audit-testing-and-invariants` based solely on surface keywords (`Foundry`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `smart-contract-audit-testing-and-invariants` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: smart-contract-audit-testing-and-invariants
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284, CWE-682, CWE-362`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`smart-contract-audit-static-analysis-tooling`](../smart-contract-audit-static-analysis-tooling/SKILL.md) - Blockchain (leaf)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `smart-contract-audit-testing-and-invariants` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-682, CWE-362`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (10), CYBER_CPT/hacktricks_cloud (3), CYBER_CPT/ctftime (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
