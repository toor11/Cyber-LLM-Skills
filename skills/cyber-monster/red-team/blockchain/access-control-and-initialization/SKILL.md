---
name: access-control-and-initialization
description: "Finds smart contract access control and initialization flaws: unprotected initializers, missing modifiers, proxy admin mistakes and privilege escalation paths. Use when contracts have privileged roles or upgradeable proxies."
family: blockchain
tier: core
triggers: ["contract access control", "uninitialized proxy", "upgrade admin", "missing modifier"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-122]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Access Control and Initialization - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Who can call what, and whether the answer changes after deployment. The audit covers modifier coverage on privileged functions, initialiser and re-initialiser paths, proxy admin authority, and role grant/revoke semantics. The characteristic bugs are an unguarded initialiser, a privilege that can be re-granted after renouncing, and a proxy whose admin is an EOA with no rotation plan.

- **Initialisation is a one-time authorisation.** An implementation that can be re-initialised after deployment hands ownership to whoever calls it first.
- **Renouncing is not revoking.** A role that can be re-granted makes renouncement theatre; check the grant path before treating renouncement as final.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the contract is behind a proxy **THEN** check `_disableInitializers()` in the implementation constructor and the admin slot value before reviewing logic.
2. **IF** a privileged function has no modifier **THEN** look for an inline check before concluding it is unguarded, because both forms appear in real code.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a complete list of privileged functions and the authority each requires — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Solidity with OpenZeppelin `AccessControl` or `Ownable2Step`, proxy patterns (transparent, UUPS, beacon), and Foundry tests for each authority boundary
- **First Check:** `forge test --match-test testAccessControl -vvv`

1. Confirm the target surface: list every state-changing function, mark which ones require authority, and identify the mechanism (modifier, inline require, role check) for each.
2. Choose the branch: initialiser review for deployment-time authority, role review for runtime grants, and proxy-admin review for upgrade authority.
3. Define the differential: call each privileged function from an unauthorised address and require a revert; a success is the finding, and the differential is that call.
4. Name the stop condition: every privileged function has a demonstrated unauthorised revert, or is recorded as an open finding with the missing check.
5. Prove it: a test per privileged function asserting revert for an unauthorised caller and success for the authorised one, so both directions are covered.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``initializer` modifier plus `_disableInitializers()`` | Prevents re-initialisation of the implementation and double-initialisation of the proxy. |
| `Role admin hierarchy in `AccessControl`` | Determines who can grant a role; a role whose admin is itself is effectively unrevokable. |
| `EIP-1967 admin slot value` | The upgrade authority; an EOA here is a single point of failure that must be documented. |
| `Unauthorised-call test per privileged function` | The only proof that a guard is present and reachable. |

## Worked Contrast

**Unguarded Initialiser and Re-grantable Role:**

```solidity
contract Vault {
    address public owner;
    bool public initialised;

    function initialize(address o) external {
        require(!initialised, "init"); // BUG: any caller can be first
        initialised = true;
        owner = o;
        }

    function renounceOwnership() external {
        require(msg.sender == owner);
        owner = address(0); // BUG: no way back, but also nothing revoked
    }

    function setFee(uint256 f) external {
        require(msg.sender == owner);
        fee = f; // BUG: fee is uninitialised and settable by whoever wins the init race
    }
}
```

**Disabled Initialiser and Explicit Two-Step Authority:**

```solidity
contract Vault is Initializable, AccessControl {
    bytes32 public constant ADMIN = keccak256("ADMIN");
    uint256 public fee;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address admin) external initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN, admin);
        fee = 100;
    }

    function setFee(uint256 f) external onlyRole(ADMIN) {
        require(f <= 1000, "fee above cap");
        fee = f;
    }
}
```

**Why this matters:** An initialiser any caller can win lets an attacker become the owner before the deployer's transaction lands, and a fee with no bound means the resulting authority is unlimited. Disabling initialisers on the implementation, granting roles explicitly in the initialiser, and bounding the privileged value keep deployment-time authority with the deployer and make the privileged action's range finite.

## When It Is NOT This Issue

- **Initialiser guarded by a factory-only pattern.** A check on `msg.sender` against a factory address is a valid guard; read it before reporting.
- **Role granted to a timelock.** The authority is the timelock's governance process; that is a design property, not a missing check.
- **Upgrade authority held by a multisig.** Documented trust assumption; the finding is only if the authority is an EOA with no rotation plan.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `access-control-and-initialization` based solely on surface keywords (`initializer`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `access-control-and-initialization` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: access-control-and-initialization
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `access-control-and-initialization` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (3), CYBER_CPT/hacktricks_cloud (1), CYBER_CPT/infocon (1), CYBER_CPT/gh_security_lab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
