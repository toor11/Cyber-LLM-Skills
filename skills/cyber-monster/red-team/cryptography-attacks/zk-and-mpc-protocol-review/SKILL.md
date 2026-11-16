---
name: zk-and-mpc-protocol-review
description: Reviews zero-knowledge and multi-party computation designs for soundness and trust assumptions, including trusted setup, commitment binding and range-check gaps. Use when assessing zk circuits or MPC protocols.
family: cryptography-attacks
tier: leaf
triggers: ["zero knowledge review", "zk circuit", "mpc protocol", "trusted setup", "soundness"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Zk and Mpc Protocol Review - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Zero-knowledge and multi-party protocol review is a design review, not a code audit, because the defects are properties of the construction rather than of an implementation detail. Four properties decide most of it. Completeness and soundness: a proof system is only as strong as its soundness error, which for a non-interactive proof is set by the challenge space — a 128-bit challenge gives at most 128-bit soundness, and a Fiat-Shamir transform that hashes less than the full transcript lets a prover fix the challenge. Knowledge soundness and the witness: a protocol that proves "a witness exists" without binding the witness to the public statement proves nothing about the statement. Zero-knowledge: the simulator argument must hold for the actual transcript, which fails if the verifier learns a commitment's opening or if the challenge is reused across sessions. Trusted setup: a universal or circuit-specific setup is a secret that must be destroyed, and a setup ceremony whose participants are not independent provides no guarantee. For MPC the corresponding questions are who learns the output, whether the adversary model is honest-majority or dishonest-majority, and whether the protocol commits to inputs before learning others' inputs.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the protocol is non-interactive **THEN** start with the Fiat-Shamir transcript: what exactly is hashed into the challenge, and is the full statement included.
2. **IF** the proof is over a public statement **THEN** check that the witness is bound to that statement and not merely to a commitment.
3. **IF** there is a setup phase **THEN** ask who held the toxic waste, whether the ceremony had independent participants, and whether the artefacts are verifiable.
4. **IF** the protocol is MPC **THEN** state the adversary model and the output disclosure before reviewing any code; a protocol that is secure in one model and deployed in another is the common finding.
5. **IF** the construction is a commitment scheme **THEN** check both binding and hiding, and whether the same commitment is reused across contexts.
6. **IF** the review is about signature schemes built on a proof system **THEN** keep this skill for the soundness argument and use [`signature-and-mac-attacks`](../signature-and-mac-attacks/SKILL.md) for the encoding.
7. **IF** the target is a blockchain verifier contract **THEN** also check the verifier's public-input handling, because a mismatch there breaks the binding even with a sound proof.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Write the claim in one sentence.** "The prover knows `w` such that `R(x, w)`" or "the parties compute `f` without revealing inputs". A protocol with no written claim cannot be reviewed, and most findings are a mismatch between the claim and the construction.
2. **Enumerate the transcript.** What the verifier sees, in what order, and what binds one message to the next. The binding is where Fiat-Shamir and commitment defects live.
3. **Choose the property under review.** Soundness, knowledge binding, zero-knowledge, setup trust, or MPC disclosure. Each has a distinct argument and a distinct counterexample.
4. **Define the baseline-vs-probe differential.** Baseline: an honest transcript verifies and reveals only the claimed output. Probe: a transcript with a modified public statement, a replayed challenge, or a substituted commitment. The differential is acceptance, or the extra information the probe extracts.
5. **Name the stop condition.** Stop at the first probe that is accepted when it should be rejected, or the first value the probe learns that the claim says it should not. Do not attempt to extract a witness.
6. **State the proof.** Report the claim, the transcript element that fails to bind, the probe, and the construction change (hash the full statement, bind the commitment, add domain separation). If every probe is rejected, record `Verified Safe` with the property you tested.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A challenge derived from a hash of only the commitment | Fiat-Shamir without the statement, so a prover can choose a statement after the challenge | In-house SNARK verifiers, sigma-protocol code |
| A verifier that takes public inputs from calldata without binding them to the proof | The proof is sound but about a different statement, which is the most common on-chain finding | Solidity verifier contracts |
| A commitment reused across two contexts with no domain separator | Cross-context replay: the same opening is valid in both places | Voting, auction, and credential schemes |
| A setup artefact with no record of participants or entropy | Trusted setup with unverifiable provenance, so the toxic waste may exist | Circuit-specific ceremonies |
| An MPC protocol stated as "secure" with no adversary model | The claim is incomplete, and honest-majority assumptions are routinely violated by one colluding party | Threshold signing, private aggregation |
| A proof system with a 64-bit challenge space | Soundness capped at 64 bits, so a cheating prover succeeds with `2^-64` effort | Hand-tuned Fiat-Shamir parameters |

## Worked Contrast

**Vulnerable: Fiat-Shamir over the commitment only, public inputs unbound**

```python
# The challenge ignores the public statement, and the verifier accepts inputs from
# the caller without binding them to the proof, so a valid proof can be replayed
# against a different statement.
import hashlib

def challenge(commitment: bytes) -> bytes:
    return hashlib.sha256(commitment).digest()          # statement not included

def verify(proof: tuple[bytes, bytes, bytes], public_inputs: list[int]) -> bool:
    a, c, z = proof
    if challenge(a) != c:                                # only the commitment binds
        return False
    return check_relation(a, c, z)                       # public_inputs unused
```

**Hardened: challenge over the full transcript, inputs bound before verification**

```python
# The challenge hashes the domain, the verifier key, the commitments, and the full
# public input vector, so a proof cannot be moved to another statement or context.
import hashlib
import struct

DOMAIN = b"zkp-v1|circuit-7|"

def challenge(vk_digest: bytes, commitments: tuple[bytes, ...], public_inputs: list[int]) -> bytes:
    h = hashlib.sha256(DOMAIN + vk_digest)
    for c in commitments:
        h.update(struct.pack(">I", len(c)) + c)
    for x in public_inputs:
        h.update(struct.pack(">Q", x))
    return h.digest()

def verify(proof, public_inputs, vk_digest: bytes) -> bool:
    a, c, z = proof
    if challenge(vk_digest, (a,), public_inputs) != c:
        return False
    return check_relation(a, c, z, public_inputs)        # inputs are part of the check
```

**Why this matters:** The left verifier's challenge depends only on a commitment, so a prover can fix the commitment, obtain the challenge, and then choose a statement — and the public inputs never enter the check at all. The right verifier hashes a domain-separated transcript that includes the verifier key and every public input, and passes those inputs into the relation check, so a proof is bound to exactly one statement.

## When It Is NOT This Issue

- **An interactive protocol where the challenge comes from the verifier.** Fiat-Shamir defects do not apply; the verifier's randomness is the challenge.
- **A trusted setup with a published, multi-party ceremony and verifiable artefacts.** The trust assumption is explicit and auditable; record it rather than filing it.
- **An MPC protocol used only among parties who all see the output anyway.** Output disclosure is the design, so the privacy claim is about inputs, not outputs.
- **A commitment that is used once and discarded.** Cross-context replay needs a second context.
- **A proof system with a documented 128-bit challenge and a matching soundness target.** The parameter meets its stated bound.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `zk-and-mpc-protocol-review` based solely on surface keywords (`trusted setup`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `zk-and-mpc-protocol-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: zk-and-mpc-protocol-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `zk-and-mpc-protocol-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/gh_advisories (3), CYBER_CPT/ctf_search (1), CYBER_CPT/osv (1), CYBER_CPT/exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
