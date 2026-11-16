---
name: bridge-and-cross-chain
description: "Assesses bridge and cross-chain designs: message verification gaps, replay and signature threshold flaws, and wrapped asset accounting. Use when funds move between chains."
family: blockchain
tier: leaf
triggers: ["bridge exploit", "cross chain attack", "message verification", "wrapped asset"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-442]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Bridge and Cross Chain - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Cross-chain systems trust a message that a different chain produced: a validator set's signatures, a light-client proof, or an oracle attestation. The audit question is what exactly is verified before value is released — the message content, its source chain and contract, its uniqueness, and the threshold of signers — and what happens when any of those checks is missing.

- **Replay protection is per-message, not per-chain.** A message that can be submitted twice, or on a second destination contract, is a double spend even with valid signatures.
- **Source chain and contract identity must be in the signed payload.** A signature over an amount without the source domain is reusable wherever the verifier accepts it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the verifier checks signatures **THEN** establish what is inside the signed digest before checking the signature scheme, because a correct signature over the wrong payload is the common bug.
2. **IF** the destination accepts any signer set **THEN** check whether that set can be changed by a message from the same bridge.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the signed payload schema, the verification path on the destination, and the replay-protection mechanism — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Solidity with the bridge's message struct and threshold signature verification, plus Foundry tests for replay and for a wrong source domain
- **First Check:** `forge test --match-test testBridgeReplay -vvv`

1. Confirm the target surface: the message struct, what the digest covers, the verifier, and the storage that records processed messages.
2. Choose the branch: signature review for threshold and domain separation, replay review for the processed-message record, and asset review for wrapped-token mint and burn symmetry.
3. Define the differential: submit the same message twice and require the second to revert; submit a message with an altered source chain and require rejection. The differential is the revert.
4. Name the stop condition: every field of the digest accounted for, and one replay test per message type.
5. Prove it: a test that a duplicate message reverts and a test that a wrong-source message reverts, plus the digest definition quoted in the report.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Message digest including source chain and contract` | Domain separation; without these fields a signature is valid on any chain and any verifier. |
| `Processed-message mapping or nonce` | The replay guard; its absence makes every valid message reusable. |
| `Signature threshold and signer set update path` | Determines who can move value and whether that set can be changed by the bridge itself. |
| `Mint and burn symmetry for wrapped assets` | An asymmetry between the two sides is an inflation path independent of the message layer. |

## Worked Contrast

**Signature Over Amount Only, No Replay Record:**

```solidity
contract Bridge {
    mapping(address => bool) validators;

    function release(bytes32 hash, uint256 amount, bytes[] calldata sigs) external {
        bytes32 digest = keccak256(abi.encodePacked(amount)); // BUG: no source chain, no nonce, no destination
        uint256 valid;
        for (uint256 i; i < sigs.length; i++) {
            if (validators[recover(digest, sigs[i])]) valid++;
        }
        require(valid >= 2, "threshold");
        token.transfer(msg.sender, amount); // BUG: replayable indefinitely
    }
}
```

**Domain-Separated Digest With a Processed Record:**

```solidity
contract Bridge {
    mapping(address => bool) validators;
    mapping(bytes32 => bool) public processed;
    uint256 public immutable sourceChainId;

    function release(bytes32 messageId, address to, uint256 amount, bytes[] calldata sigs) external {
        require(!processed[messageId], "already processed");
        bytes32 digest = keccak256(abi.encode(
            sourceChainId, address(this), messageId, to, amount
        ));
        uint256 valid;
        for (uint256 i; i < sigs.length; i++) {
            if (validators[recover(digest, sigs[i])]) valid++;
        }
        require(valid >= threshold, "threshold");
        processed[messageId] = true;
        token.transfer(to, amount);
    }
}
```

**Why this matters:** A digest over the amount alone is valid on every chain and for every message with that amount, so one signature releases funds repeatedly, and with no processed record even a unique message can be resubmitted. Including the source chain, the destination contract, a unique message id and the recipient in the digest, plus recording the id before transferring, makes the message single-use and bound to one route.

## When It Is NOT This Issue

- **Signature count below threshold because of duplicates.** Repeated signers in one message should count once; check the deduplication before reporting a threshold bypass.
- **Validator set updated by governance.** A legitimate rotation path is a trust assumption; the finding is an unauthorised update path.
- **Wrapped asset mint without a burn on the source.** Expected for a lock-and-mint bridge; asymmetry is only a finding when both sides can mint.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `bridge-and-cross-chain` based solely on surface keywords (`message verify`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `bridge-and-cross-chain` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: bridge-and-cross-chain
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-345`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `bridge-and-cross-chain` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/blackhills (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
