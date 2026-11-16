---
name: constant-time-and-crypto-side-channel-code-audit
description: "Audits cryptographic and authentication routines for software timing/cache side channels: early-exit byte comparison (`==` instead of `hmac.compare_digest` / `subtle.ConstantTimeCompare`), secret-dependent branches or table lookups, and BigInt normalization leaks. Use when reviewing MAC, token, or scalar-math verification code."
family: cryptography-attacks
tier: leaf
triggers: ["timing attack code review", "hmac.compare_digest", "constant time comparison", "secret branch leak"]
cwe: [CWE-208]
owasp: []
attack: []
capec: []
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
corpus_sparse: true
---

# Constant Time and Crypto Side Channel Code Audit - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Constant-time review asks whether the time or the memory-access pattern of a secret-dependent operation depends on the secret. The classic sources are: a branch conditioned on a secret (`if (mac[i] != expected[i]) return false;` exits at the first differing byte, leaking the matching prefix length), a table lookup indexed by a secret byte (an S-box or a base64 alphabet indexed by key material, which shows up in cache-line timing), a division or modulo by a secret (variable-latency on most cores and the direct cause of the KyberSlash timing findings in ML-KEM reference code), and a comparison compiled from a language-level `==` that the optimiser is free to short-circuit. Defending requires a primitive whose running time is a function of public lengths only: `hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`, or an explicit XOR-accumulate-and-mask. The audit is complicated by the fact that source-level constant-time code is not enough — the compiler may reintroduce a branch or a division, which is exactly what happened when Clang turned a masked select in ML-KEM's `poly_frommsg` into a secret-dependent branch under specific optimisation levels. So the review questions are: is the operation secret-dependent, is the primitive constant-time at the source level, and has anyone verified the emitted code.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a MAC, tag, token, or password hash is compared with `==`, `===`, or `memcmp` **THEN** that is the finding; the replacement is a library constant-time compare over equal-length buffers.
2. **IF** a secret indexes an array or a table **THEN** the branch is cache-timing: check whether the table is small enough to stay in cache, and whether a bitsliced or masked alternative exists.
3. **IF** the operation divides or takes a modulo by a value derived from a secret **THEN** treat it as a timing leak on variable-latency hardware; the remediation is a multiply-and-shift or a fixed-time reduction.
4. **IF** the leak is in a post-quantum primitive (ML-KEM, ML-DSA) **THEN** pair this skill with [`post-quantum-cryptography-migration-and-hybrids`](../post-quantum-cryptography-migration-and-hybrids/SKILL.md) and check the implementation version against the published timing findings.
5. **IF** the comparison is between a user-supplied identifier and a database key **THEN** check whether the lookup itself is the oracle (a query returning faster for a miss), which is a different proof obligation.
6. **IF** the comparison is in a test, a CLI, or an offline tool **THEN** it is a code-quality note; state that the path is unreachable from an untrusted caller.
7. **IF** you need the operational view of timing distributions **THEN** pivot to [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the secret-dependent operation.** Grep for comparison, indexing, and division on values that come from key material, a MAC, a token, or a password hash. Record the operand provenance for each hit; a comparison of two public values is not in scope.
2. **Classify the leak channel.** Early-exit branch (prefix length leaks), table index (cache line leaks), variable-latency arithmetic (operand-value leaks), or length leak (the length of a secret is itself secret). Each has a different fix and a different measurement.
3. **Check the primitive, then the emitted code.** Confirm the library call is documented constant-time, then check whether the build is one where the compiler reintroduced a branch — optimisation level, target architecture, and library version all matter.
4. **Define the baseline-vs-probe differential.** Baseline: measure the operation with inputs that differ only in the first byte of the secret. Probe: same measurement with inputs differing in the last byte. A constant-time implementation shows overlapping distributions at any sample size; a leaking one shows a shift that grows with sample count.
5. **Name the stop condition.** Stop when the distributions separate beyond the measured noise floor with a stated sample size, or when the source-level primitive is provably constant-time and the build is a known-good one. Do not run a full key-recovery campaign.
6. **State the proof.** Report the operation, the channel class, the measured or source-level differential, the affected build, and the replacement primitive. If the comparison is already `compare_digest` and the buffer lengths are fixed, the outcome is `Verified Safe`.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `if computed == expected:` on a hex MAC or a token | Early-exit comparison, so an attacker learns the matching prefix length per request | Python, Ruby, PHP password and token checks |
| `bytes.Equal(a, b)` in a Go MAC check | `bytes.Equal` short-circuits; `subtle.ConstantTimeCompare` does not | Go services, gRPC interceptors |
| `strcmp(tag, expected)` in C | Compiler- and libc-dependent early exit, plus a length oracle from the null terminator | C/C++ verifiers, firmware |
| Secret byte used as an index into a 256-entry table | Cache-line timing leak whose severity depends on table size and co-residency | AES S-box code, base64 alphabet maps |
| `/ KYBER_Q` or `% secret` in a KEM or signature path | Variable-latency division, the causal pattern in the KyberSlash findings | ML-KEM/ML-DSA reference and embedded ports |
| `hmac.compare_digest(a, b)` after an explicit length check | Constant-time comparison with a documented length precondition — the correct shape | Python stdlib, `cryptography`, Django |

## Worked Contrast

**Vulnerable: early-exit comparison and secret-indexed lookup**

```python
# `==` on a MAC stops at the first differing byte, so response time tracks how
# many leading bytes the attacker guessed correctly. The table index leaks too.
def verify(request_tag: bytes, secret: bytes) -> bool:
    expected = hmac.new(secret, request_tag, "sha256").digest()
    if request_tag == expected:            # early exit: prefix-length oracle
        return True
    return False

def xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ SBOX[key[i % len(key)]] for i, b in enumerate(data))  # secret index
```

**Hardened: constant-time compare over fixed-length buffers, no secret indexing**

```python
# compare_digest runs in time proportional to the buffer length only, and the
# key stream is produced by a vetted primitive instead of a table lookup.
import hmac

def verify(request_tag: bytes, secret: bytes, expected_len: int = 32) -> bool:
    if len(request_tag) != expected_len:      # length is public, checked first
        return False
    expected = hmac.new(secret, request_tag, "sha256").digest()
    return hmac.compare_digest(request_tag, expected)   # no early exit

def xor_with_key(data: bytes, key: bytes) -> bytes:
    stream = hmac.new(key, b"stream", "sha256").digest() * (len(data) // 32 + 1)
    return bytes(a ^ b for a, b in zip(data, stream))   # no secret-indexed table
```

**Why this matters:** The left comparison hands an attacker a per-request prefix oracle that turns a 32-byte tag into 32 independent byte guesses, and the table index adds a cache channel on top. The right version removes both: `compare_digest` touches every byte regardless of where they differ, and the keystream comes from a hash rather than from an array indexed by key material.

## When It Is NOT This Issue

- **`==` on a public identifier, a nonce, or a version string.** Nothing secret is compared, so the timing carries no information. Say so explicitly rather than filing it.
- **A length check before a constant-time compare.** Revealing the length of a *public* tag format is not a leak; the constant-time property applies to the secret bytes.
- **A comparison in a code path that requires an authenticated admin session.** The oracle exists but the attacker already holds the privilege it would reveal; record it as a hardening note.
- **Timing differences from database or network variance.** A 200 µs p99 shift on a route with a 20 ms network floor is noise. Compute the noise floor before claiming a channel.
- **A table lookup whose index is public.** AES S-box indexed by plaintext is not the same leak as one indexed by the key; check the provenance of the index before flagging.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `constant-time-and-crypto-side-channel-code-audit` based solely on surface keywords (`hmac.compare_digest`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `constant-time-and-crypto-side-channel-code-audit` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: constant-time-and-crypto-side-channel-code-audit
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-208`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `constant-time-and-crypto-side-channel-code-audit` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-208`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
