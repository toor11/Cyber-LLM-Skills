---
name: symmetric-cipher-attacks
description: "Attacks symmetric encryption: key reuse, weak key derivation, nonce and IV mistakes, mode-specific weaknesses and known-plaintext exploitation. Use when AES, DES, ChaCha or similar is used in application logic or a challenge."
family: cryptography-attacks
tier: core
triggers: ["aes attack", "symmetric crypto attack", "nonce reuse", "iv reuse", "ecb pattern"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [symmetric-cipher-attacks-keystream-and-nonce-reuse, symmetric-cipher-attacks-weak-key-derivation, classical-and-covert-encoding, block-cipher-modes-and-padding-oracles]
---

# Symmetric Cipher Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Symmetric attack review is mostly about mode and key lifecycle, because the primitives themselves — AES, ChaCha20 — are not the weak point. Stream constructions (CTR, OFB, CFB, ChaCha20) generate a keystream from `(key, nonce)` and XOR it with the plaintext, so a repeated `(key, nonce)` XORs two plaintexts together and reveals their difference; recovering either plaintext then reveals the other, and with a known plaintext the keystream is directly readable. Block constructions (ECB, CBC) have their own equality and malleability properties, which the block-cipher child skills cover. The third axis is key lifecycle: a key derived from a password without a KDF, a key shared across tenants, or a key that never rotates concentrates the consequences of any one defect. The fourth is the IV derivation, which is where most real stream findings live — a counter that resets on process restart, a nonce derived from a timestamp with second resolution, or an IV that is `random()` from a non-cryptographic generator. In review the deterministic question is: for a given key, is the `(nonce)` space large enough and consumed without repetition, and does a plaintext ever repeat under the same nonce.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the construction is CTR, OFB, CFB, or ChaCha20 **THEN** check the nonce source and the restart behaviour first; a reset counter is the most common real defect.
2. **IF** the construction is ECB or CBC **THEN** switch to [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md); the arithmetic is different.
3. **IF** the same `(key, nonce)` pair appears twice in any sample **THEN** switch to [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](../symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md) for the recovery arithmetic.
4. **IF** the key comes from a password or a short secret **THEN** switch to [`symmetric-cipher-attacks-weak-key-derivation`](../symmetric-cipher-attacks-weak-key-derivation/SKILL.md).
5. **IF** the key is shared across tenants or record classes **THEN** the finding is blast radius, and the fix is key separation, not a mode change.
6. **IF** the construction is an AEAD with a per-message nonce and a full tag **THEN** this class mostly closes; route the remaining questions to [`aead-aes-gcm-and-chacha20-misuse`](../aead-aes-gcm-and-chacha20-misuse/SKILL.md).
7. **IF** the IV is derived from a timestamp or a database sequence **THEN** measure the collision probability under the actual write rate before filing.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `symmetric-cipher-attacks-keystream-and-nonce-reuse` | [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](../symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `symmetric-cipher-attacks-weak-key-derivation` | [`symmetric-cipher-attacks-weak-key-derivation`](../symmetric-cipher-attacks-weak-key-derivation/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the construction and the counter state.** Mode, key width, nonce width, and where the counter lives — memory, disk, or derived. A counter in process memory resets on restart, which is the finding in most service deployments.
2. **Enumerate the nonce space and the consumption rate.** `2^64` messages is fine; `2^32` with a restart reset is not. Compare the space to the deployment's actual volume.
3. **Choose the branch.** Nonce lifecycle (reset, reuse, too narrow), key lifecycle (shared, unrotated, weakly derived), or construction (unauthenticated stream). Each has a different proof.
4. **Define the baseline-vs-probe differential.** Baseline: encrypt the same plaintext twice with the production path and observe two distinct ciphertexts. Probe: restart the process or rewind the counter and observe the same ciphertext prefix. Identical ciphertext for identical plaintext is the repeat.
5. **Name the stop condition.** Stop at the first reproduced `(key, nonce)` repeat. Do not XOR production ciphertexts to recover plaintext.
6. **State the proof.** Report the construction, the nonce source, the repeat mechanism (restart, rollback, narrow counter), and the consequence for confidentiality and integrity. If the nonce is per-message from a CSPRNG at adequate width, record `Verified Safe`.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `Counter.new(128)` recreated per process start | The counter resets, so the first messages after each restart share a nonce | PyCryptodome CTR call sites, Java `IvParameterSpec` |
| `int(time.time())` as the nonce | Second-resolution time means a collision whenever two messages land in one second | Hand-rolled stream encryption |
| One key constant used by every tenant's rows | Blast radius: one leaked key exposes all tenants, and any reuse is global | Multi-tenant services with a shared `ENCRYPTION_KEY` |
| `AES.new(key, AES.MODE_CTR, nonce=os.urandom(8))` per message | Per-message random nonce with adequate width; a control at realistic volumes | Modern PyCryptodome usage |
| A stream cipher with no MAC | Integrity is absent, so a bit flip is undetected; the finding is the missing authentication, not the keystream | `AES/CTR/NoPadding`, raw ChaCha20 |
| A key version field read before decryption | Rotation is possible, which bounds the blast radius of one key | Mature envelope formats |

## Worked Contrast

**Vulnerable: counter recreated per process, one key for all tenants**

```python
# The counter starts at zero on every process start, so the first message after a
# restart reuses a nonce under the same key. One key for every tenant widens it.
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY = b"0" * 32

def encrypt_row(tenant: str, plaintext: bytes) -> bytes:
    ctr = Counter.new(128)                  # resets on every start
    return AES.new(KEY, AES.MODE_CTR, counter=ctr).encrypt(plaintext)
```

**Hardened: per-message random nonce, per-tenant key, authenticated**

```python
# A fresh 96-bit random nonce per message, a per-tenant DEK, and GCM's tag so a
# bit flip is detected. No counter state to reset.
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_row(tenant_key: bytes, tenant: str, row_id: str, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    aad = f"v1|t={tenant}|r={row_id}".encode()
    return nonce + AESGCM(tenant_key).encrypt(nonce, plaintext, aad)
```

**Why this matters:** The left construction reuses a nonce after every restart and across tenants, so the keystream repeats and two ciphertexts XOR to the XOR of their plaintexts; nothing detects a modification because there is no tag. The right construction takes randomness from the OS per message, scopes the key to one tenant, and authenticates both the ciphertext and its identity.

## When It Is NOT This Issue

- **A CTR nonce that is a random 64-bit value with a bounded message count.** The collision probability is negligible at realistic volumes; compute it rather than assuming.
- **A counter persisted in a database with an atomic increment.** No reset on restart, so the lifecycle is sound even though the design is stateful.
- **A stream cipher used to generate keystream for a masking operation with no plaintext.** No plaintext to protect, so reuse leaks only the mask.
- **A shared key in a single-tenant deployment.** Blast radius arguments need more than one tenant to matter.
- **A nonce derived from a monotonic message id that never repeats.** Sound, and often better than random; record the source.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `symmetric-cipher-attacks` based solely on surface keywords (`ECB`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `symmetric-cipher-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: symmetric-cipher-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](../symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks-weak-key-derivation`](../symmetric-cipher-attacks-weak-key-derivation/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `symmetric-cipher-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 41 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (31), hackerone_disclosed_reports (2), CYBER_CPT/ctf_search (2), CYBER_CPT/ctftime (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
