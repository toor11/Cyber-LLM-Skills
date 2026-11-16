---
name: wallet-and-key-management-attacks-key-generation-weakness
description: Wallet key generation weakness. Covers weak entropy sources, nonce reuse in signing and key derivation mistakes in wallet software. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: blockchain
tier: leaf
triggers: ["wallet weak key", "entropy weakness", "nonce reuse wallet"]
cwe: [CWE-321]
owasp: []
attack: []
capec: [CAPEC-59]
related: [wallet-and-key-management-attacks, wallet-and-key-management-attacks-approval-and-permit-abuse, smart-contract-audit, defi-attack-patterns]
parent: wallet-and-key-management-attacks
---


# Wallet and Key Management Attacks Key Generation Weakness - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

Key generation and derivation: the entropy source behind a private key, the derivation path used for a hierarchical wallet, and the nonce used in a signature. The characteristic failures are a key derived from a timestamp or a low-entropy seed, a derivation path reused across accounts, and a reused ECDSA nonce which reveals the private key from two signatures.

- **Entropy is invisible in the output.** A key from a predictable source looks like any other key, so the review must reach the generator rather than judge the key.
- **Nonce reuse is total compromise.** Two signatures over different messages with the same `k` yield the private key algebraically; the audit check is whether `k` can be deterministic or repeated.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the code generates a key **THEN** trace the entropy source to the operating system's CSPRNG and reject any timestamp, counter, or `Math.random` in the path.
2. **IF** the code signs **THEN** confirm the library uses RFC 6979 deterministic nonces or a hardware RNG, because a repeated `k` is unrecoverable.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the key generation path, the derivation scheme, and the signing implementation — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** CSPRNG-backed key generation (`secrets`, `os.urandom`, or the platform keystore), BIP-32/BIP-39 derivation, and RFC 6979 deterministic ECDSA
- **First Check:** `python -c "import secrets; print(len(secrets.token_bytes(32)))"`

1. Confirm the target surface: where keys are created, where the seed comes from, which derivation path is used, and which signing library is linked.
2. Choose the branch: entropy review for generation, derivation review for path reuse and account isolation, and signing review for nonce determinism.
3. Define the differential: for entropy, attempt to reproduce a generated key from the purported source; for nonces, sign two messages and compare the `r` value, which is equal exactly when `k` repeats.
4. Name the stop condition: every key path traces to a CSPRNG and every signature path uses a deterministic or hardware nonce.
5. Prove it: the source of entropy quoted with its call chain, and the two-signature `r` comparison for the nonce check.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``secrets.token_bytes(32)` or the platform keystore` | The only acceptable entropy sources; anything derived from time or a counter is predictable. |
| `BIP-32 derivation path per account` | Path reuse across accounts links them on-chain and collapses the isolation the wallet claims. |
| `RFC 6979 deterministic ECDSA` | Removes nonce reuse by deriving `k` from the key and message. |
| `Equal `r` across two signatures` | The direct test for nonce reuse, because `r` is a function of `k` alone. |

## Worked Contrast

**Time-Seeded Key and Library Nonce Handling:**

```python
import time
from ecdsa import SigningKey, SECP256k1

seed = int(time.time() * 1000) % (2**32)  # BUG: timestamp entropy, trivially enumerable
sk = SigningKey.from_secret_exponent(seed, curve=SECP256k1)

sig1 = sk.sign(b"transfer:1")
sig2 = sk.sign(b"transfer:2")
# BUG: a library with a weak or repeated nonce leaks the key from these two signatures
```

**CSPRNG Key With Deterministic Nonces:**

```python
import secrets
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string

seed = int.from_bytes(secrets.token_bytes(32), "big")  # CSPRNG entropy
sk = SigningKey.from_secret_exponent(seed, curve=SECP256k1)

sig1 = sk.sign_deterministic(b"transfer:1", hashfunc=__import__("hashlib").sha256, sigencode=sigencode_string)
sig2 = sk.sign_deterministic(b"transfer:2", hashfunc=__import__("hashlib").sha256, sigencode=sigencode_string)
assert sig1[:32] != sig2[:32], "r must differ between distinct messages"
```

**Why this matters:** A key seeded from a millisecond timestamp has at most a few million candidates, so an attacker who knows roughly when the wallet was created can enumerate the key space; and a signing path without deterministic nonces can repeat `k`, which reveals the private key from two signatures. Drawing 32 bytes from the CSPRNG and signing deterministically removes both, and comparing the `r` component across two signatures is a direct test that nonces differ.

## When It Is NOT This Issue

- **Key generated inside a hardware wallet.** The entropy is the device's; the review question is the device's certification, not the host's RNG.
- **Same `r` across two signatures from the same message.** Identical messages produce identical signatures; the test needs distinct messages.
- **Derivation path shared by design.** A single-account wallet has one path; the finding is path reuse across accounts that the wallet presents as isolated.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `wallet-and-key-management-attacks-key-generation-weakness` based solely on surface keywords (`weak entropy`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wallet-and-key-management-attacks-key-generation-weakness` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: wallet-and-key-management-attacks-key-generation-weakness
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-321`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks-approval-and-permit-abuse`](../wallet-and-key-management-attacks-approval-and-permit-abuse/SKILL.md) - Blockchain (leaf)
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wallet-and-key-management-attacks-key-generation-weakness` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/expku (1), CYBER_CPT/pentesterlab (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
