---
name: ecc-and-diffie-hellman-attacks
description: "Attacks elliptic curve and Diffie-Hellman usage: invalid curve points, small subgroup confinement, parameter validation gaps and weak curves. Use when ECDH, ECDSA or custom curve parameters are in play."
family: cryptography-attacks
tier: core
triggers: ["ecc attack", "elliptic curve", "diffie hellman attack", "invalid curve", "small subgroup"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Ecc and Diffie Hellman Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Elliptic-curve review has four distinct failure classes, and confusing them is the most common source of bad reports. The first is invalid-curve and small-subgroup attacks: if a peer-supplied point is not validated to lie on the curve and in the correct subgroup, an attacker can force the shared secret into a small set and recover the private scalar one residue at a time; the defence is cofactor multiplication and an on-curve check, which is why X25519 multiplies by the cofactor and rejects the all-zero output. The second is parameter trust: explicit curve parameters that the receiver accepts from the wire allow invalid twist curves or a composite order. The third is ECDSA nonce quality: a repeated or biased `k` leaks the private key algebraically from two signatures (or from one signature plus a lattice step when only a few bits of `k` are known), and deterministic RFC 6979 derivation removes the RNG from the equation. The fourth is implementation, including ladder and scalar-multiplication timing, which is where constant-time discipline applies. The precondition across all four is that the attacker can supply a point, observe a signature, or measure a computation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the protocol accepts a public key or a point from the peer and uses it without an on-curve and subgroup check **THEN** the invalid-curve branch applies; the proof is a point that produces a shared secret outside the intended subgroup.
2. **IF** the curve parameters arrive with the key rather than being named by identifier **THEN** the parameter-trust branch applies and the finding is about what the receiver fails to validate, not about the maths.
3. **IF** two signatures over different messages share a nonce, or a nonce is derived from a predictable source **THEN** switch to [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md) for the recovery arithmetic and keep this skill for the curve-level context.
4. **IF** the issue is a weak or legacy curve (P-192, a 160-bit binary field, `secp112r1`) **THEN** report it as a strength finding with the claimed security level, not as a break.
5. **IF** the implementation is a modern library with X25519 or P-256 and a documented validation step **THEN** the disposition is `Verified Safe`; name the library call that performs the check.
6. **IF** the protocol is a post-quantum hybrid **THEN** pair with [`post-quantum-cryptography-migration-and-hybrids`](../post-quantum-cryptography-migration-and-hybrids/SKILL.md); the combiner is a separate review.
7. **IF** the target is a TLS handshake with an ECDHE exchange **THEN** start at [`tls-and-pki-attacks`](../tls-and-pki-attacks/SKILL.md) for the negotiation context, then return here for the point validation.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the group and the validation contract.** Record the curve identifier, whether parameters are implicit or explicit, and the exact validation the receiver performs before using a peer point. Absent an on-curve check, the rest follows.
2. **Establish what the attacker controls.** A point, a scalar, a signature, or only timing. Each maps to one branch; a review that mixes them produces unactionable findings.
3. **Choose the branch and its arithmetic.** Invalid curve: a point on a small-order twist forces the shared secret into a tiny set. Parameter trust: substitute a curve the receiver accepts. Nonce: two signatures with equal `r` share `k`. Strength: compare the curve's order to the claimed bit level.
4. **Define the baseline-vs-probe differential.** Baseline: a valid peer point produces a shared secret with full entropy. Probe: an off-curve point either raises a validation error or produces a secret that repeats across different private scalars. The second outcome is the finding.
5. **Name the stop condition.** Stop at the first proof that a non-conforming point is accepted, or the first observation that a derived secret is independent of the private scalar. Do not attempt scalar recovery.
6. **State the proof.** Report the curve, the validation step that is missing, the probe point's provenance (a known small-order point on a specific twist), and the consequence (secret confinement, key recovery, signature forgery). If validation rejects the probe, the finding is closed.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `ECDH_compute_key` with no `EC_POINT_is_on_curve` before it | The receiver uses a peer point unvalidated, which is the invalid-curve precondition | OpenSSL low-level ECDH, custom TLS stacks |
| `EC_KEY_set_group` from a received `ECParameters` blob | Explicit parameter trust: the receiver adopts whatever curve the peer names | ASN.1-decoding paths, older Java `AlgorithmParameters` |
| Two ECDSA signatures with equal `r` | Identical nonce `k`, so the private key is recoverable from `s1 - s2` algebraically | Any ECDSA signer without deterministic nonces |
| `k = int.from_bytes(os.urandom(32)) % n` with a comment about bias | Modular reduction of a uniform 256-bit value into a 256-bit order is nearly unbiased, but the pattern signals hand-rolled nonce logic that needs review | Home-rolled signers |
| `secp192r1` or a 160-bit binary curve in a config | Strength below the current floor, so the finding is degradation rather than breakage | Legacy protocol configs, embedded TLS |
| X25519 with an all-zero shared-secret check | Correct validation: the library rejects the low-order output, so the branch is closed | libsodium, BoringSSL, Go `crypto/ecdh` |

## Worked Contrast

**Vulnerable: peer point used without an on-curve or subgroup check, and a nonce from a weak RNG**

```python
# The peer's point is fed straight into the scalar multiplication. If it lies on a
# small-order twist, the shared secret lands in a tiny set and the scalar leaks a
# residue per connection. The nonce is hand-rolled from the platform RNG.
from cryptography.hazmat.primitives.asymmetric import ec
import random

def agree(peer_point: ec.EllipticCurvePublicKey, priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.exchange(ec.ECDH(), peer_point)     # no validation step

def nonce(n: int) -> int:
    return random.randrange(1, n)                    # predictable, non-cryptographic
```

**Hardened: validated point, vetted group, deterministic nonce**

```python
# The peer key is rebuilt through the library's own decoder, which rejects a point
# that is not on the curve and not in the subgroup. The nonce is RFC 6979.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CURVE = ec.SECP256R1()

def agree(peer_der: bytes, priv: ec.EllipticCurvePrivateKey) -> bytes:
    peer = serialization.load_der_public_key(peer_der)      # validation happens here
    if not isinstance(peer.curve, ec.SECP256R1):
        raise ValueError("unexpected group")
    secret = priv.exchange(ec.ECDH(), peer)
    if secret == b"\x00" * len(secret):                      # low-order guard
        raise ValueError("degenerate shared secret")
    return secret

def sign(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg, ec.ECDSA(hashes.SHA256()))         # deterministic per RFC 6979
```

**Why this matters:** The left version accepts a point the attacker chose, so a small-order point confines the shared secret to a handful of values and each handshake reveals one residue of the private scalar; the random nonce adds a second, independent key-recovery path. The right version forces the point through a decoder that rejects off-curve and wrong-group inputs, guards the degenerate output, and delegates nonce generation to a deterministic scheme the RNG cannot weaken.

## When It Is NOT This Issue

- **X25519 or P-256 through a modern library with an implicit validation contract.** `cryptography`, BoringSSL, and Go's `crypto/ecdh` reject non-conforming points internally. Confirm the library version and record the call as a control.
- **A peer point that fails the on-curve check.** The probe is rejected, which is the definition of a non-finding; cite the exception you observed.
- **A short curve in an offline test fixture.** Test vectors for P-192 are not a production strength finding unless the same curve is reachable in the deployed config.
- **Two signatures with equal `r` where the signer is deterministic.** RFC 6979 produces the same `k` for the same message, so equal `r` on identical messages is expected. Only different messages with equal `r` matter.
- **Timing variation in a scalar multiplication that operates on a public point.** The scalar is secret, the point is public, and the leak requires attacker visibility into cache state; state the co-residency assumption before filing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `ecc-and-diffie-hellman-attacks` based solely on surface keywords (`invalid curve`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ecc-and-diffie-hellman-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: ecc-and-diffie-hellman-attacks
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ecc-and-diffie-hellman-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/ctftime (3), OffsecCyber (1), ctf-solver-dataset (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
