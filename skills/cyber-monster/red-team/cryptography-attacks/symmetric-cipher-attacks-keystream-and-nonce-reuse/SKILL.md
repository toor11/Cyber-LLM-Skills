---
name: symmetric-cipher-attacks-keystream-and-nonce-reuse
description: Keystream and nonce reuse. Covers stream cipher and CTR nonce reuse, keystream recovery by XOR, and the consequences across protocols. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["keystream reuse", "ctr nonce reuse", "stream cipher attack"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [symmetric-cipher-attacks, symmetric-cipher-attacks-weak-key-derivation, classical-and-covert-encoding, block-cipher-modes-and-padding-oracles]
parent: symmetric-cipher-attacks
---

# Symmetric Cipher Attacks Keystream and Nonce Reuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Keystream reuse is the arithmetic of a repeated `(key, nonce)` under a stream construction. Encryption is `C = P xor KS` where `KS` depends only on the key and nonce, so two ciphertexts under the same pair satisfy `C1 xor C2 = P1 xor P2`. That equality alone is useful: it reveals where two plaintexts agree and where they differ, which for structured plaintext (JSON, HTML, protocol headers) recovers most of the content by crib-dragging. If either plaintext is known, the keystream is `KS = C xor P` and the other plaintext is immediate. In CTR mode the counter is part of the nonce, so the reuse can be a *block* rather than a message: two messages whose counters overlap in one block reuse that block's keystream, which is why a counter that resets mid-message or a random 64-bit nonce used as a 128-bit counter start produces partial overlap. In CBC the analogue is a repeated IV for the first block only. The precondition is a repeat you can demonstrate, and the proof is a differential between two ciphertexts, not a decrypted secret.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** two ciphertexts share a nonce **THEN** XOR them and look for plaintext structure; that differential is the finding and it needs no key.
2. **IF** the counter is built from a random start value **THEN** check the width: a random 64-bit start in a 128-bit counter means two messages can overlap in a block, which is partial reuse.
3. **IF** one plaintext is guessable or known **THEN** the keystream is recoverable and the second plaintext follows; state the crib you used.
4. **IF** the construction is CBC with a repeated IV **THEN** the reuse is confined to the first block; measure whether that block carries structure worth recovering.
5. **IF** the construction is an AEAD **THEN** the same repeat also exposes the GHASH key; route that half to [`aead-aes-gcm-and-chacha20-misuse`](../aead-aes-gcm-and-chacha20-misuse/SKILL.md).
6. **IF** the nonce space is adequate and the source is a CSPRNG or a persisted counter **THEN** record `Verified Safe` with the space arithmetic.
7. **IF** the repeat requires an attacker to control the nonce **THEN** the finding is a nonce-control bug in the API, not a reuse bug in the construction.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish the construction and the nonce width.** CTR, OFB, CFB, or ChaCha20, and whether the counter includes a fixed part. The width decides whether reuse is per message or per block.
2. **Find a repeat.** Collect ciphertexts from the production path, group by the nonce bytes if they are stored, and check for duplicates. If nonces are not stored, reproduce the path offline and drive the counter to a repeat.
3. **Choose the branch.** Full-message reuse, partial block overlap, or known-plaintext keystream recovery. Each gives a different amount of plaintext, and the report should say which.
4. **Define the baseline-vs-probe differential.** Baseline: ciphertexts under two distinct nonces XOR to noise. Probe: ciphertexts under one nonce XOR to structure — repeated byte patterns, ASCII runs, or a known header. The structure is the proof.
5. **Name the stop condition.** Stop at the first XOR that shows structure or a known header. Do not attempt to recover a full message from production data.
6. **State the proof.** Report the two ciphertexts' nonce values, the XOR's structural evidence, the crib if used, and the plaintext extent recovered. If no repeat exists at the stated volume, record the negative with the collision arithmetic.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Two rows with identical 12-byte nonce prefixes | Full-message keystream reuse, so the two plaintexts XOR to a readable difference | Stored ciphertext tables, audit exports |
| A random 64-bit counter start used as a 128-bit counter | Partial block overlap between two messages with probability bounded by the message count over `2^64` | PyCryptodome `Counter.new(128, initial_value=...)` |
| `nonce = b"\x00" * 12` on a stream cipher | Every message reuses the keystream, so the whole corpus is XOR-related | Test code promoted to production |
| XOR of two ciphertexts yields repeated 16-byte patterns | ECB-like equality inside a stream, which means the plaintexts share a block | Structured JSON or XML plaintext |
| A persisted counter with an atomic increment and a stored value | No reuse at any volume short of overflow; the control to cite | Database-backed nonce sequences |
| Identical ciphertext for two identical plaintexts | Immediate reuse, visible without any analysis | Any deterministic stream path |

## Worked Contrast

**Vulnerable: a fixed nonce, so every message shares one keystream**

```python
# A constant nonce means C1 xor C2 == P1 xor P2 for every pair of messages. With
# one known plaintext, every other message decrypts.
from Crypto.Cipher import ChaCha20

NONCE = b"\x00" * 12

def seal(key: bytes, plaintext: bytes) -> bytes:
    return ChaCha20.new(key=key, nonce=NONCE).encrypt(plaintext)
```

**Hardened: unique nonce per message from a CSPRNG, with the nonce stored alongside**

```python
# A fresh 96-bit nonce per message, stored with the ciphertext so decryption has
# no shared state, and an AEAD tag so modification is detected too.
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def seal(key: bytes, plaintext: bytes, context: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, context)
```

**Why this matters:** The left function gives every message the same keystream, so the whole corpus is related by XOR and one known or guessed plaintext decrypts the rest. The right function draws a fresh nonce per message from the OS and binds the ciphertext to its context with a tag, so no two messages share a keystream and modification is detected.

## When It Is NOT This Issue

- **A nonce derived from a monotonic id that is never reused, even if predictable.** Predictability is not reuse; a counter is a correct nonce source.
- **A repeated IV under CBC where only the first block is affected and that block is a random salt.** The reuse leaks equality of the salt, not plaintext.
- **A random nonce collision at a volume far below the birthday bound.** Show the arithmetic; a `2^-40` probability is not a finding.
- **A keystream reused deliberately for a masking operation with no plaintext.** Nothing to recover.
- **Identical ciphertexts produced by a deterministic encryption feature that is documented.** Deterministic encryption leaks equality by design; the finding is the feature, not the reuse.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `symmetric-cipher-attacks-keystream-and-nonce-reuse` based solely on surface keywords (`keystream`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `symmetric-cipher-attacks-keystream-and-nonce-reuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: symmetric-cipher-attacks-keystream-and-nonce-reuse
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`symmetric-cipher-attacks-weak-key-derivation`](../symmetric-cipher-attacks-weak-key-derivation/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `symmetric-cipher-attacks-keystream-and-nonce-reuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/ctftime (4), CYBER_CPT/github_security_md (1), CYBER_CPT/ctf_wiki (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
