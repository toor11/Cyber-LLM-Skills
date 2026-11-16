---
name: prng-and-nonce-attacks-signature-nonce-reuse
description: Signature nonce reuse. Covers ECDSA and DSA nonce reuse to recover private keys, including partial nonce leakage through lattices. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["ecdsa nonce reuse", "dsa nonce", "private key recovery"]
cwe: [CWE-338]
owasp: []
attack: []
capec: [CAPEC-59]
related: [prng-and-nonce-attacks, prng-and-nonce-attacks-predictable-token-generation, classical-and-covert-encoding, symmetric-cipher-attacks]
parent: prng-and-nonce-attacks
---

# PRNG and Nonce Attacks Signature Nonce Reuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

An ECDSA or DSA signature is `(r, s)` with `r = x(kG)` and `s = k^-1 (z + r*d) mod n`, so the nonce `k` is the only per-signature randomness and the private key `d` is linear in it. Two signatures over different messages that share `k` give two equations in two unknowns: `s1*k - r1*d = z1` and `s2*k - r2*d = z2` mod `n`, which solve directly for `d`. Equal `k` is observable as equal `r` because `r` depends only on `k` and the generator point. The softer variant is a biased `k`: if each nonce is small, or its top bits are zero, or a byte repeats, then each signature leaks a few bits of the linear relation and a lattice (hidden number problem) recovers `d` from enough signatures — the bias needed shrinks with the number of signatures, and a handful of signatures with 8 known bits each is enough. The same algebra applies to RSA-PSS only through the salt, and to any scheme where a per-message random value enters a linear equation. The precondition is two signatures under one key, or many biased ones, plus the message hashes, all of which are public.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** two signatures under one key share `r` **THEN** the nonce repeated and the private key follows from two equations; this is the strongest form and the proof is a one-line subtraction.
2. **IF** the nonces are biased rather than repeated **THEN** the branch is a hidden-number lattice; estimate the known bits per signature and the signature count before claiming feasibility.
3. **IF** the signer uses `ecdsa` with a `random` module source **THEN** the generator is not cryptographic and the finding stands on the API; route the generator half to [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md).
4. **IF** the signer derives `k` deterministically per RFC 6979 **THEN** equal `r` on the same message is expected and is a control; only equal `r` on different messages matters.
5. **IF** the scheme is Ed25519 or EdDSA **THEN** the nonce is derived from the key and the message by construction, so this class does not apply.
6. **IF** the target uses RSA-PKCS#1 v1.5 signatures **THEN** switch to [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md); the failure mode is padding, not nonces.
7. **IF** you have only one signature and no bias information **THEN** **STOP**: one equation with two unknowns has no solution, and the disposition is `Not Reproducible`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Collect the public artefacts.** Two or more signatures under the same key, the message hashes (`z`), and the curve order `n`. All of this is public; nothing here requires the key.
2. **Group by `r`.** Sort signatures by the `r` value. A repeated `r` across different `z` is the repeated-nonce case and needs no further analysis.
3. **Choose the branch.** Repeated nonce (two equations), biased nonce (lattice with a stated bias), or no signal (close it). Record which one and why.
4. **Define the baseline-vs-probe differential.** Baseline: signatures under a deterministic signer show distinct `r` for distinct messages. Probe: two signatures with equal `r` and different `z`. The differential is the equality, and it is visible in public data alone.
5. **Name the stop condition.** Stop at the demonstrated equal-`r` pair, or at the measured bias when it exceeds the lattice bound. Do not compute a private key from production signatures.
6. **State the proof.** Report the two message hashes, the shared `r`, the algebraic relation that follows, and the remediation (RFC 6979 or a CSPRNG-backed nonce with a stated width). For the bias branch, report the measured bias and the signature count against the bound.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Two signatures, different `z`, identical `r` | Repeated nonce, so `d = (s1*z2 - s2*z1) / (r*(s1 - s2))` mod n — recoverable from public data | Any ECDSA or DSA signer with a weak RNG |
| `k = int.from_bytes(os.urandom(32), "big") % n` | Slight non-uniformity only; a bias too small to exploit, so this is usually a control | Hand-rolled signers with a CSPRNG |
| `ecdsa.sign(..., k=random.randrange(1, n))` | Non-cryptographic nonce source, so state recovery and repetition are both possible | Python `ecdsa` misuse, test harnesses |
| Nonces whose top 8 bits are always zero | Hidden-number input, exploitable from tens of signatures rather than two | Smart cards and HSMs with a biased RNG |
| Deterministic RFC 6979 signing | Same message gives the same `r`, different messages give different `r`; a control | `cryptography`, BoringSSL, libsecp256k1 |
| Ed25519 signatures | Nonce derived from key and message, so no per-signature randomness exists to leak | libsodium, Go `ed25519` |

## Worked Contrast

**Vulnerable: nonce from a non-cryptographic generator**

```python
# `random.randrange` is MT19937: its state is recoverable from outputs, and a
# repeated k makes two signatures solve for the private key with no search at all.
import random
from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigencode_string

sk = SigningKey.generate(curve=NIST256p)

def sign(msg_hash: bytes) -> bytes:
    k = random.randrange(1, NIST256p.order)          # predictable nonce
    return sk.sign_digest_deterministic(msg_hash, hashfunc=None,
                                        sigencode=sigencode_string,
                                        k=k) if False else sk.sign_digest(msg_hash, k=k, sigencode=sigencode_string)
```

**Hardened: deterministic nonce per RFC 6979, or a CSPRNG of full width**

```python
# Deterministic k means no RNG is involved, so no bias and no repetition is
# possible; the same message always produces the same signature.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sk = ec.generate_private_key(ec.SECP256R1())

def sign(msg: bytes) -> bytes:
    der = sk.sign(msg, ec.ECDSA(hashes.SHA256()))     # RFC 6979 inside the library
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
```

**Why this matters:** The left signer's nonce comes from a generator whose state leaks, and any repeat of `k` turns two public signatures into a linear system for the private key. The right signer derives `k` from the key and the message hash, so `k` is unique per message by construction and there is no randomness to observe, bias, or repeat.

## When It Is NOT This Issue

- **Equal `r` on the same message hash.** A deterministic signer (RFC 6979) produces the same signature for the same message; that is the design, not a leak.
- **Two signatures under different keys with equal `r`.** The algebra needs one key; equal `r` across keys is a coincidence or a shared generator, and the finding is about the generator's seed, not the nonce.
- **Ed25519 or EdDSA signatures.** No per-signature nonce exists, so the class does not apply.
- **A modest nonce bias under a CSPRNG.** A `% n` reduction of a 256-bit value for a 256-bit order introduces a bias far below any feasible lattice bound; quantify it before filing.
- **Test-vector signatures in a fixture.** Published vectors deliberately reuse values; they prove the implementation matches the spec.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `prng-and-nonce-attacks-signature-nonce-reuse` based solely on surface keywords (`nonce reuse`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prng-and-nonce-attacks-signature-nonce-reuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: prng-and-nonce-attacks-signature-nonce-reuse
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-338`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md) - Cryptography Attacks (core)
- [`prng-and-nonce-attacks-predictable-token-generation`](../prng-and-nonce-attacks-predictable-token-generation/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prng-and-nonce-attacks-signature-nonce-reuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-338`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 32 |
| Distinct dataset sources | 16 |
| Top sources | OffsecCyber (7), SecEval/cs161_textbook (4), CYBER_CPT/atomic_red_team (3), SecEval/owasp_mastg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
