---
name: rsa-attacks-signature-forgery
description: RSA signature forgery. Covers signature forgery through e=3 and lax parsing, hash comparison gaps, and textbook RSA signing misuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["rsa signature forgery", "rsa signature attack", "textbook rsa"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-463]
related: [rsa-attacks, rsa-attacks-small-and-low-exponent, rsa-attacks-factorization, rsa-attacks-padding-oracle]
parent: rsa-attacks
corpus_sparse: true
---

# Rsa Attacks Signature Forgery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

RSA signature forgery in review is almost always a verifier bug rather than a key problem. The signature operation is `s = m^d mod n` and verification recovers `m' = s^e mod n` and compares it to the expected encoding, so the security depends entirely on how strictly `m'` is checked. Three verifier defects are common. First, `e=3` with a hand-rolled verifier that only checks a prefix of the recovered block: an attacker computes the cube root of a chosen encoding (a value that starts with the expected prefix and ends with the hash they want) and obtains a valid signature because the check never reaches the divergent middle. Second, verifiers that parse ASN.1 leniently and ignore trailing bytes, so a signature over one message is accepted for another that shares the prefix. Third, verifiers that compare hashes with `==` or accept a hash algorithm identifier from the signature itself, which permits algorithm substitution. The precondition is a verifier that does not implement the full EMSA-PKCS1-v1_5 or PSS comparison, which in practice means code that calls a raw modexp instead of a library's verify function.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the verifier calls a raw modular exponentiation and then parses the result itself **THEN** this is the skill; the strictness of that parse is the whole question.
2. **IF** `e` is 3 **THEN** compute whether a cube-root forgery lands in the accepted prefix region; this is arithmetic on the encoding, not a search.
3. **IF** the verifier ignores trailing bytes or accepts a shorter encoding **THEN** that is the branch regardless of `e`.
4. **IF** the algorithm identifier comes from the signature blob **THEN** the branch is algorithm substitution, which is a separate finding from the parse depth.
5. **IF** the code calls `Signature.verify` or an equivalent library function with PSS or v1.5 mode **THEN** the disposition is a control; record the mode.
6. **IF** the scheme is PSS **THEN** the parse-depth defects do not apply, because PSS verification is a full-block comparison with a random salt.
7. **IF** the target is RSA decryption rather than verification **THEN** switch to [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md).

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

1. **Read the verify function, not the sign function.** Locate the code that recovers `m'` and the exact comparison it performs: full byte equality, a prefix, a parsed ASN.1 structure, or a hash comparison.
2. **Determine the accepted region.** For a prefix check, the set of recoverable blocks the verifier accepts. For a lenient parse, the tolerated trailing bytes. That set is the attack surface.
3. **Choose the branch.** Cube-root forgery (small `e` with a prefix check), trailing-byte acceptance, or algorithm substitution. Each has its own construction.
4. **Define the baseline-vs-probe differential.** Baseline: a genuine signature verifies. Probe: a forged or appended signature either verifies, or fails at a specific check. The differential is the acceptance, and the specific rejection point tells you which check saved it.
5. **Name the stop condition.** Stop at the first forged or modified signature the verifier accepts, on an offline copy of the verifier. Do not submit to a production verifier.
6. **State the proof.** Report the verifier, the accepted region, the forged encoding's structure, and the minimal fix (use the library's verify, compare the full block, or require the exact expected length). If the verifier rejects every probe at the full-block comparison, record `Verified Safe`.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `pow(sig, e, n)` followed by a hand-written prefix comparison | Raw modexp with a partial check, so the accepted region is larger than the encoding | Firmware verifiers, licence checks |
| `Arrays.equals(rec, expected)` on the full modulus-length block | Full-block comparison, which closes the forgery branch | Correct library usage |
| `Arrays.equals(Arrays.copyOf(rec, 8), prefix)` | Prefix-only check: the rest of the block is unconstrained | Hand-rolled signature code |
| A verifier that reads the digest OID from the signature blob | Algorithm substitution: an attacker picks the weakest digest | ASN.1-parsing verifiers |
| `e = 3` with `RSASSA-PKCS1-v1_5` and a library verify | Safe: the library enforces the full encoding even at `e=3` | JCA, Go, `cryptography` |
| A verifier that accepts a signature shorter than the modulus length | Length laxity, which usually indicates a parse that pads rather than rejects | Custom binary formats |

## Worked Contrast

**Vulnerable: raw modexp with a prefix comparison**

```python
# Recovering m' by hand and comparing only the first bytes leaves the middle of the
# block unconstrained, so an e=3 forgery only needs to match the prefix.
def verify(sig: bytes, expected_prefix: bytes, pub) -> bool:
    m = pow(int.from_bytes(sig, "big"), pub.e, pub.n)
    rec = m.to_bytes(pub.size_in_bytes(), "big")
    return rec.startswith(expected_prefix)          # the rest is unconstrained
```

**Hardened: library verification of the full encoding**

```python
# The library recomputes the expected encoding and compares the whole block, so no
# part of the recovered value is left unconstrained.
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def verify(sig: bytes, message: bytes, pub) -> bool:
    try:
        pub.verify(sig, message,
                   padding.PKCS1v15(),           # full EMSA comparison inside
                   hashes.SHA256())
        return True
    except InvalidSignature:
        return False
```

**Why this matters:** The left verifier accepts any block whose first bytes match, which at `e=3` is directly constructible by taking a cube root of a chosen encoding. The right verifier reconstructs the entire expected encoding from the message and the hash and compares it against the recovered block, so there is no unconstrained region to exploit.

## When It Is NOT This Issue

- **`e=3` with a library verify call.** Small exponents are safe when the encoding is enforced in full; the finding would need a parse defect.
- **PKCS#1 v1.5 signatures in a protocol that requires them.** v1.5 signature encoding is not the Bleichenbacher decryption issue; only the parse strictness matters.
- **A PSS verifier.** PSS is a full-block comparison with a salt, so prefix and trailing-byte laxity do not apply.
- **A signature over a hash the caller supplies without binding to a message.** That is a protocol design issue, not a forgery primitive, unless an attacker can choose the hash.
- **A verifier in a test harness.** Fixtures often contain deliberately malformed signatures to test rejection; confirm the path is not deployed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `rsa-attacks-signature-forgery` based solely on surface keywords (`e=3 signature`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rsa-attacks-signature-forgery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: rsa-attacks-signature-forgery
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
- [`rsa-attacks-small-and-low-exponent`](../rsa-attacks-small-and-low-exponent/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-factorization`](../rsa-attacks-factorization/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rsa-attacks-signature-forgery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
