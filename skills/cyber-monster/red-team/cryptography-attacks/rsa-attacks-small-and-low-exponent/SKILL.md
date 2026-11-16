---
name: rsa-attacks-small-and-low-exponent
description: RSA small and low exponent attacks. Covers low exponent cube-root attacks, unreduced plaintext, Hastad broadcast, and Coppersmith for small roots. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["rsa small exponent", "e=3 rsa", "hastad broadcast", "coppersmith rsa"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-463]
related: [rsa-attacks, rsa-attacks-factorization, rsa-attacks-padding-oracle, rsa-attacks-signature-forgery]
parent: rsa-attacks
---

# Rsa Attacks Small and Low Exponent - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Small-exponent attacks are arithmetic on the ciphertext, not a weakness of RSA. With `e=3` and a message short enough that `m^3 < n`, encryption is an integer cube with no modular reduction, so a plaintext recovery is one integer root. The broadcast variant (Hastad) removes the size condition: if the same unpadded `m` is sent to `e` different recipients with pairwise-coprime moduli, the Chinese Remainder Theorem reconstructs `m^e` exactly over the integers, and one root recovers `m` — which is why `e=3` across three recipients with identical messages is a textbook break while the same keys with randomised padding are fine. The Franklin-Reiter related-message case applies when two messages differ by a known affine relation and share a modulus. The related precondition for review is that the application controls the padding: any scheme that prepends a fixed header and appends the message leaves the high bits constant, which is exactly the structure Coppersmith's small-root method needs to extend the attack to longer messages. The finding is therefore never "`e=3` is used" but "`e=3` is used and the plaintext is not randomised or not length-bounded".

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** `e=3` and the plaintext is shorter than `n^(1/3)` with no padding **THEN** the branch is an integer root; the recovery is one `iroot` call.
2. **IF** the same message is encrypted to three or more recipients with `e=3` **THEN** the branch is Hastad: CRT then root, independent of message length.
3. **IF** the padding is fixed-prefix with the message appended **THEN** the branch is Coppersmith, and the bound depends on how many high bits are fixed relative to `N^(1/3)`.
4. **IF** the padding is OAEP or any randomised scheme **THEN** the disposition is a control even at `e=3`; say which padding you verified.
5. **IF** `e` is 65537 **THEN** none of the integer-root branches apply, and the finding would have to be a padding or verifier defect.
6. **IF** the encryption is a signature verification path rather than a decryption path **THEN** switch to [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md).
7. **IF** the modulus is below 1024 bits **THEN** add a strength finding alongside the exponent analysis rather than instead of it.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`rsa-attacks`](../rsa-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read `e` and the padding from the encryption call.** Both are public and both decide everything. A library call with a `padding=` argument is readable; a raw modexp means no padding.
2. **Bound the message size.** For `e=3`, a message below roughly `n/8` bits is inside the no-reduction regime. Compare the application's actual plaintext lengths — a session key or a PIN is well inside it, a document is not.
3. **Choose the branch.** Integer root (single ciphertext), Hastad (several ciphertexts), or Coppersmith (fixed-prefix padding). Each has a different precondition and a different report.
4. **Define the baseline-vs-probe differential.** Baseline: a padded message does not yield a perfect root. Probe: the same message unpadded does, exactly. For Hastad, the baseline is one ciphertext (no CRT) and the probe is three.
5. **Name the stop condition.** Stop at the first exact root that produces structured plaintext (a key, a token, a readable string). Do not attempt a Coppersmith reduction on production data.
6. **State the proof.** Report `e`, the plaintext bit length against the bound, the padding scheme, and the exact root. If the padding is randomised, record `Verified Safe` and name the scheme.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `pow(int.from_bytes(m,"big"), 3)` with no padding | Raw cube: any message below `n^(1/3)` is recoverable by an integer root | Licence files, home-rolled key transport |
| The same ciphertext-length blob to three recipients, `e=3` | Hastad precondition; CRT reconstructs `m^3` exactly | Multi-recipient key wrapping, DRM |
| `RSA/ECB/NoPadding` with `e=3` | No randomisation, so the high bits of the message are fixed by the caller | JCA `Cipher` with `NoPadding` |
| `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` | Randomised padding, which defeats all three branches | Modern JCA, Go `crypto/rsa` |
| `e=65537` on a 2048-bit key | Exponent too large for integer-root attacks; a finding needs another cause | Default in every modern library |
| A fixed ASCII prefix before the message | Coppersmith structure: enough known high bits reduce the search to a small root | Custom envelope formats, firmware tokens |

## Worked Contrast

**Vulnerable: raw cube with no padding on a small message**

```python
# e=3 and no padding: a 128-bit session key cubed fits inside a 2048-bit modulus,
# so the ciphertext is an exact cube and the key is one integer root away.
def wrap_raw(session_key: bytes, n: int, e: int = 3) -> int:
    m = int.from_bytes(session_key, "big")
    return pow(m, e, n)                 # no padding, no randomisation
```

**Hardened: OAEP with a random seed, and an exponent that is not 3**

```python
# OAEP randomises the encoded message so the cube is never exact, and a 65537
# exponent removes the integer-root branch entirely.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def wrap_oaep(session_key: bytes, pub) -> bytes:
    return pub.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
```

**Why this matters:** The left wrap produces a ciphertext that is literally `m^3`, so an attacker takes a cube root and reads the session key with no key material at all; the same weakness across three recipients makes Hastad work even for long messages. The right wrap randomises the encoding before the exponentiation, which makes the result non-deterministic and the root inexact, and the larger exponent removes the arithmetic branch entirely.

## When It Is NOT This Issue

- **`e=3` with OAEP.** Randomisation defeats the integer root and Hastad; the exponent alone is not a finding.
- **`e=3` used for signatures with a full-block verifier.** Signature encoding is deterministic but the verifier enforces the full block, so the forging branch belongs to the signature skill.
- **A message longer than `n^(1/3)` with no other structure.** The integer root does not apply, and without a fixed-prefix Coppersmith structure the finding is theoretical.
- **`e=65537`.** The integer-root branches need `m^e < n`, which a 17-bit exponent makes impossible for any realistic message.
- **A test vector with a small modulus and `e=3`.** Deliberate; confirm it is not deployed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `rsa-attacks-small-and-low-exponent` based solely on surface keywords (`e=3`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rsa-attacks-small-and-low-exponent` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: rsa-attacks-small-and-low-exponent
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-326`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`rsa-attacks`](../rsa-attacks/SKILL.md) - Cryptography Attacks (flagship)
- [`rsa-attacks-factorization`](../rsa-attacks-factorization/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rsa-attacks-small-and-low-exponent` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctftime (4), CYBER_CPT/ctf_wiki (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
