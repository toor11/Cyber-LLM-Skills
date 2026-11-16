---
name: lattice-and-advanced-crypto-attacks
description: "Applies lattice reduction and advanced cryptanalysis to CTF and real constructions: LLL, Coppersmith, hidden number and knapsack problems. Use when the attack requires recovering small unknowns or solving structured linear systems."
family: cryptography-attacks
tier: leaf
triggers: ["lattice attack", "lll", "coppersmith", "hidden number", "knapsack crypto"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Lattice and Advanced Crypto Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Lattice methods are the practical answer to a specific question: given an RSA or ECDSA public key and a hint about the private values, is the remaining search small enough to solve? Coppersmith's theorem says that a monic polynomial of degree `d` modulo `N` can be solved for roots smaller than roughly `N^(1/d)`, which turns "the low 128 bits of `p` leaked" into a small-root problem over a lattice rather than a search over `2^128`. LLL and BKZ reduce a lattice basis to find a short vector, and the attacker constructs the lattice so that the short vector encodes the unknown. The three review-relevant instantiations are: a partially known prime factor (leaked bits of `p`, or `p` and `q` sharing high bits), a small RSA exponent with a short message or a linear padding relation (`Hastad`), and biased ECDSA nonces where the known bits of `k` reduce to a hidden-number-problem lattice. The precondition in all cases is a leak that the designer considered harmless — "only 64 bits" — combined with a modulus small enough that `N^(1/d)` exceeds the leak. Reviewing it means quantifying the leak against the modulus size, not looking for a code pattern.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a code path leaks high or low bits of a prime factor **THEN** compute `N^(1/2)` against the leak width; a 1024-bit `N` gives a 512-bit bound, so a 300-bit leak is solvable and a 700-bit leak is not.
2. **IF** the same message is RSA-encrypted under `e` different moduli with `e=3` **THEN** that is Hastad's broadcast case; the parent [`rsa-attacks`](../rsa-attacks/SKILL.md) carries the arithmetic and this skill carries the lattice construction.
3. **IF** a signature uses a nonce with a known bias (the top bits are zero, or a byte repeats) **THEN** the hidden-number lattice applies; route the nonce-quality half to [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md).
4. **IF** the leak is smaller than the bound **THEN** the finding is a strength-degradation note with the exact bound cited, not an exploit.
5. **IF** the modulus is 2048 bits or larger and the leak is a few bits **THEN** record the margin and close the finding as not practical at current parameters.
6. **IF** the target uses a post-quantum scheme **THEN** switch to [`post-quantum-cryptography-migration-and-hybrids`](../post-quantum-cryptography-migration-and-hybrids/SKILL.md); lattice hardness there is the design assumption, not a break.
7. **IF** you only need to decide whether a leaked value matters **THEN** stay here for the bound and do not build a lattice.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Write the leak as an equation.** Express what the system reveals as a congruence: `p ≡ p0 (mod 2^k)`, a shared high-half relation, or `k = k_known + delta` with `|delta| < 2^b`. Without a congruence there is no lattice to build.
2. **Compute the Coppersmith bound.** For a degree-`d` polynomial modulo `N`, the small root bound is about `N^(1/d)`. Compare it to the leak width. This single comparison decides whether the finding is practical, and it is arithmetic you can do by hand.
3. **Choose the construction.** Univariate small root (partial factor), multivariate linear (Hastad), or hidden-number (biased nonce). Each has a known basis shape; `fpylll` or Sage build it.
4. **Define the baseline-vs-probe differential.** Baseline: with no leak, the same lattice produces no short vector below the bound. Probe: with the leak, one basis vector is short enough to read the unknown. The differential is the norm, not a successful decrypt.
5. **Name the stop condition.** Stop when the short-vector norm is below the theoretical bound and the recovered value verifies against the public key. Do not proceed to recover a private key; the bound plus a verification of the recovered *public* consistency is enough for a report.
6. **State the proof.** Report the congruence, the leak width, the modulus size, the bound, and the margin. If the leak exceeds the bound, the finding is `Not Practical` with the arithmetic shown — that is a valid and useful outcome.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A debug endpoint returning the top 256 bits of `p` | A partial-factor leak whose solvability is `N^(1/2)` versus 256 — practical at 1024-bit `N`, not at 2048 | Key-generation diagnostics, HSM test hooks |
| `e = 3` with the same plaintext under three moduli | Hastad broadcast, solvable by CRT then a cube root with no lattice needed at `e=3` | Multi-recipient encryption, licence files |
| ECDSA signatures where the top 8 bits of `k` are zero | Hidden-number lattice input; 8 bits per signature times enough signatures recovers the key | Embedded signers, smart cards with biased RNG |
| `p` and `q` differing only in the low 512 bits | Fermat-adjacent: a shared high half makes the factorisation a small-root problem | Weak key generation, `openssl genrsa` with a bad RNG |
| `fpylll`/`sage` in a dependency list of an assessment tool | Lattice tooling is present, so bounds are checkable rather than theoretical | Assessment workstations, not production |
| A 4096-bit modulus with a 64-bit leak | Margin is enormous, so the finding is a hardening note rather than a break | Modern TLS keys |

## Worked Contrast

**Vulnerable: a diagnostic path that exposes half of a prime factor**

```python
# Returning the high half of p converts factorisation into a Coppersmith small-root
# problem: for N of 1024 bits the bound is ~2^512, so a 512-bit leak is solvable.
def key_report(priv) -> dict:
    p = priv.private_numbers().p
    return {"bits": p.bit_length(),
            "high_half": hex(p >> (p.bit_length() // 2))}   # half of p leaves the building
```

**Hardened: report only public, non-invertible properties**

```python
# Only the modulus size and a fingerprint of the PUBLIC modulus are reported.
# No function of p or q that narrows the search space is emitted.
import hashlib

def key_report(priv) -> dict:
    pub = priv.public_key().public_numbers().n
    fingerprint = hashlib.sha256(pub.to_bytes((pub.bit_length() + 7) // 8, "big")).hexdigest()[:16]
    return {"bits": pub.bit_length(), "modulus_fingerprint": fingerprint}
```

**Why this matters:** The left report hands out a value that turns a `2^512` search into a lattice computation that finishes in minutes, because the leaked half exceeds nothing — it is exactly at the bound. The right report exposes only the public modulus and a hash of it, which reveals the key's identity without revealing any function of the private factors.

## When It Is NOT This Issue

- **A leak that is below the bound but on a modulus large enough that the bound is out of reach.** A 128-bit leak on a 2048-bit modulus has a `2^1024` bound; quote the margin and close it.
- **A short public exponent with a full-length, randomly padded message.** `e=3` is fine when the padding is randomised and the message fills the modulus; Hastad needs the same unpadded message under several moduli.
- **A biased nonce where the signer has since moved to RFC 6979.** The historical signatures still leak their own keys, but the current path is closed; scope the finding to the affected key.
- **Lattice tooling in an assessment environment.** Its presence is not a production defect.
- **A shared modulus between two keys where both are public.** Shared moduli are a real finding, but it is a GCD, not a lattice; route it to [`rsa-attacks-factorization`](../rsa-attacks-factorization/SKILL.md).

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `lattice-and-advanced-crypto-attacks` based solely on surface keywords (`LLL`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `lattice-and-advanced-crypto-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: lattice-and-advanced-crypto-attacks
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `lattice-and-advanced-crypto-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctftime (4), CYBER_CPT/ctf_wiki (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
