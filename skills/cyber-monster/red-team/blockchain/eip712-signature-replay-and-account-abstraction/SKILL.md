---
name: eip712-signature-replay-and-account-abstraction
description: "Audits EIP-712 typed signatures, EIP-2612 `permit`, meta-transactions, and ERC-4337 Account Abstraction (`EntryPoint`, `validateUserOp`, Paymasters): missing `chainId` or `verifyingContract` in `DOMAIN_SEPARATOR`, `ecrecover` zero-address return on invalid `v/r/s`, signature malleability, and nonce/gas griefing in bundlers. Use when reviewing off-chain signing or smart wallets."
family: blockchain
tier: core
triggers: ["eip-712 replay", "erc-4337 audit", "ecrecover zero address", "domain_separator chainid", "validateuserop"]
cwe: [CWE-347, CWE-294]
owasp: []
attack: []
capec: []
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
corpus_sparse: true
---


# Eip712 Signature Replay and Account Abstraction - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Signature-based authorisation under EIP-712 and account abstraction: a typed digest scoped by domain (`name`, `version`, `chainId`, `verifyingContract`), a nonce that makes each signature single-use, and — for smart accounts — the fields covered by `userOpHash` and the initialisation path. The characteristic failures are a digest that omits a field the action depends on, a nonce not bound to the signer, and an initialiser an attacker can call before the owner.

- **Every field the action depends on must be in the digest.** A relayer that supplies a recipient not covered by the signature can redirect the result while the signature stays valid.
- **7702 initialisation is a race.** An account that delegates code and initialises in separate transactions is open to an attacker initialising first; the safe pattern requires the account to be the caller.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a relayer submits the transaction **THEN** check that every value the relayer controls is inside the signed digest, not beside it.
2. **IF** the account is an EIP-7702 delegation **THEN** verify the initialiser requires `msg.sender == address(this)` and is single-use.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the digest schema, the nonce mechanism, and for smart accounts the validation and initialisation paths — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** EIP-712 typed data with an explicit domain, a per-signer nonce, and ERC-4337 validation that binds all UserOperation fields
- **First Check:** `cast call $CONTRACT 'DOMAIN_SEPARATOR()(bytes32)' --rpc-url $RPC`

1. Confirm the target surface: the typed data structure, the domain fields, the nonce storage, and who submits the transaction.
2. Choose the branch: EIP-712 review for the digest contents, nonce review for replay across signers and chains, and account-abstraction review for `userOpHash` coverage and initialisation.
3. Define the differential: replay the same signature twice and require the second to fail; then alter each field the relayer controls and require rejection. A field that can change without invalidating the signature is the finding.
4. Name the stop condition: every relayer-controlled field is either inside the digest or explicitly validated against the signature.
5. Prove it: a test per altered field showing rejection, and a replay test showing the nonce is consumed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``DOMAIN_SEPARATOR` with name, version, chainId, verifyingContract` | Binds the signature to one contract on one chain; omitting `chainId` makes it replayable across forks. |
| `Per-signer nonce incremented on use` | Prevents replay; a global nonce serialises unrelated users and a missing nonce allows unlimited reuse. |
| ``userOpHash` covering gas and fee fields` | An account that validates only `callData` lets a bundler inflate `preVerificationGas` and drain the account. |
| `Initialiser requiring `msg.sender == address(this)`` | The 7702 pattern that prevents an attacker initialising a delegated account first. |

## Worked Contrast

**Digest Missing the Recipient, No Nonce:**

```solidity
contract Forwarder {
    function execute(address to, uint256 amount, bytes calldata sig) external {
        // BUG: `to` is not in the digest, so the relayer can redirect the transfer
        bytes32 digest = keccak256(abi.encode(amount));
        require(ECDSA.recover(digest, sig) == owner, "bad sig");
        // BUG: no nonce, so the same signature can be replayed
        token.transfer(to, amount);
    }
}
```

**Full Digest With a Per-Signer Nonce:**

```solidity
contract Forwarder {
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    bytes32 constant TRANSFER_TYPEHASH = keccak256("Transfer(address to,uint256 amount,uint256 nonce)");

    function execute(address to, uint256 amount, uint256 nonce, bytes calldata sig) external {
        require(nonce == nonces[owner], "bad nonce");
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, to, amount, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        require(ECDSA.recover(digest, sig) == owner, "bad sig");
        nonces[owner] = nonce + 1;
        token.transfer(to, amount);
    }
}
```

**Why this matters:** A digest over the amount alone lets a relayer substitute any recipient while the signature still verifies, and the missing nonce lets the same signature be used repeatedly. Including the recipient and a per-signer nonce in the typed struct, and prefixing the domain separator, binds the signature to exactly one action by one signer on one contract.

## When It Is NOT This Issue

- **Signature rejected on second use.** That is the nonce working; a signature accepted twice is the finding.
- **Chain-id zero in a 7702 delegation.** It widens the replay surface and should be reported as a risk, but it is a user choice rather than a program defect.
- **`ecrecover` returning zero for a malformed signature.** The missing check is the finding, not the zero address itself.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `eip712-signature-replay-and-account-abstraction` based solely on surface keywords (`DOMAIN_SEPARATOR`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `eip712-signature-replay-and-account-abstraction` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: eip712-signature-replay-and-account-abstraction
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-347, CWE-294`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `eip712-signature-replay-and-account-abstraction` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, CWE-294`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
