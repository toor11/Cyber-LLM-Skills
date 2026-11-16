---
name: wallet-and-key-management-attacks
description: "Attacks wallet and key handling: weak key generation, signing request confusion, approval abuse and key storage exposure. Use when the target involves wallets, signers or custody."
family: blockchain
tier: core
triggers: ["wallet attack", "private key exposure", "approval abuse", "signature phishing"]
cwe: [CWE-321]
owasp: []
attack: []
capec: [CAPEC-59]
related: [wallet-and-key-management-attacks-approval-and-permit-abuse, wallet-and-key-management-attacks-key-generation-weakness, smart-contract-audit, defi-attack-patterns]
---


# Wallet and Key Management Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

The key and approval surface around a protocol or user: how private keys are generated and stored, what token approvals exist and to whom, and how signatures are requested and verified. The parent skill frames the three questions — entropy, custody, and authority — and the children handle approvals and key generation.

- **Approval is standing authority.** An unlimited approval is a permanent grant; the audit question is who can spend and whether anything bounds it in time or amount.
- **Entropy failures are silent.** A key derived from a weak source looks like any other key until it is swept, so the review must reach the generation path rather than the key's appearance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target resolves to `wallet-and-key-management-attacks-approval-and-permit-abuse` **THEN** switch to [`wallet-and-key-management-attacks-approval-and-permit-abuse`](../wallet-and-key-management-attacks-approval-and-permit-abuse/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
2. **IF** the target resolves to `wallet-and-key-management-attacks-key-generation-weakness` **THEN** switch to [`wallet-and-key-management-attacks-key-generation-weakness`](../wallet-and-key-management-attacks-key-generation-weakness/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
3. **IF** the system holds approvals **THEN** enumerate spender, allowance, and token per account before anything else, because that is the blast radius.
4. **IF** the system signs messages **THEN** check the domain separator, the nonce, and the deadline before checking the signature algorithm.
5. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
6. **IF** the input cannot establish the precondition this skill needs — the key generation path, the approval inventory, and the signature verification code — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `wallet-and-key-management-attacks-approval-and-permit-abuse` | [`wallet-and-key-management-attacks-approval-and-permit-abuse`](../wallet-and-key-management-attacks-approval-and-permit-abuse/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `wallet-and-key-management-attacks-key-generation-weakness` | [`wallet-and-key-management-attacks-key-generation-weakness`](../wallet-and-key-management-attacks-key-generation-weakness/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** On-chain allowance reads via `cast`, signature verification review with EIP-712 domain fields, and a key-generation review of the entropy source
- **First Check:** `cast call $TOKEN 'allowance(address,address)(uint256)' $OWNER $SPENDER --rpc-url $RPC`

1. Confirm the target surface: identify where keys are generated, where they are stored, and which contracts hold approvals from the accounts in scope.
2. Choose the branch: approval review for standing authority, key-generation review for entropy and derivation, or signature review for replay and malleability.
3. Define the differential: for approvals, compare the granted allowance against the intended amount and duration; for signatures, replay the same signature twice and require the second to fail.
4. Name the stop condition: every approval above a threshold accounted for, or an explicit statement that the approval set is unbounded by design.
5. Prove it: the allowance read at a stated block, the spender contract, and for signatures the second-use revert, so the grant or its absence is demonstrated.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``allowance(owner, spender)` read at a block` | The factual state of standing authority, independent of any UI or claim. |
| `Spender contract identity and whether it is upgradeable` | An approval to an upgradeable spender can change meaning without the owner acting again. |
| `Signature nonce and deadline` | The two fields that prevent replay; their absence is the finding, not the algorithm. |
| `Entropy source in key generation` | Weak or predictable randomness produces keys that look normal and are trivially derivable. |

## Worked Contrast

**Unbounded Approval With No Deadline:**

```solidity
contract Router {
    function pull(IERC20 token, address from, uint256 amount) external {
        // BUG: relies on an unlimited approval and never checks the deadline
        token.transferFrom(from, address(this), amount);
    }
    function permit(address owner, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        // BUG: deadline accepted as a parameter but never enforced
        IERC20Permit(address(this)).permit(owner, address(this), value, deadline, v, r, s);
    }
}
```

**Bounded Approval and Enforced Deadlines:**

```solidity
contract Router {
    IERC20 public immutable token;

    constructor(IERC20 t) { token = t; }

    function pull(address from, uint256 amount) external {
        require(amount <= maxPull, "amount above cap");
        require(token.allowance(from, address(this)) >= amount, "allowance too low");
        token.transferFrom(from, address(this), amount);
    }

    function permitAndPull(address owner, uint256 value, uint256 deadline,
                           uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        IERC20Permit(address(token)).permit(owner, address(this), value, deadline, v, r, s);
        token.transferFrom(owner, address(this), value);
    }
}
```

**Why this matters:** An approval is authority that persists, so a router that pulls an arbitrary amount through an unlimited allowance turns one signature into an unbounded grant, and accepting a deadline without comparing it to the block timestamp makes the parameter decorative. Bounding the pull and enforcing the deadline keep the authority the owner granted inside the window and amount they intended.

## When It Is NOT This Issue

- **Unlimited approval to a well-known immutable router.** A common pattern with a documented trust assumption; record it rather than treating it as a defect.
- **Permit signature that fails on second use.** That is the nonce working; a signature accepted twice would be the finding.
- **Key stored in a hardware wallet or KMS.** The entropy question is about generation, not storage, when the storage is a device that generates internally.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `wallet-and-key-management-attacks` based solely on surface keywords (`approval abuse`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wallet-and-key-management-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: wallet-and-key-management-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-321`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`wallet-and-key-management-attacks-approval-and-permit-abuse`](../wallet-and-key-management-attacks-approval-and-permit-abuse/SKILL.md) - Blockchain (leaf)
- [`wallet-and-key-management-attacks-key-generation-weakness`](../wallet-and-key-management-attacks-key-generation-weakness/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wallet-and-key-management-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 4 |
| Top sources | cyber-security/CyberSec-Dataset (6), CYBER_CPT/expku (4), CYBER_CPT/go_exploitdb (2), SecEval/android_sec_doc (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
