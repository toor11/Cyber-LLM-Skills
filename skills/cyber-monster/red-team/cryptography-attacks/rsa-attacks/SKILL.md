---
name: rsa-attacks
description: "Attacks RSA implementations: small exponent and low exponent conditions, common modulus, Wiener and Hastad, faulty padding, oracle attacks, and weak key generation. Use when RSA is present with observable ciphertexts or a public key."
family: cryptography-attacks
tier: flagship
triggers: ["rsa attack", "rsa ctf", "small exponent", "common modulus", "wiener attack", "rsa oracle"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-463]
related: [rsa-attacks-small-and-low-exponent, rsa-attacks-factorization, rsa-attacks-padding-oracle, classical-and-covert-encoding]
---

# Rsa Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **flagship** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

RSA failures under review sort into four mathematical families, and the choice between them is decided by arithmetic on the public key, not by code shape. Small or structured exponents: `e=3` with an unpadded message admits an integer cube root, and the same message under `e` different moduli (Hastad) admits a CRT combination then a root. Weak factorisation: shared primes across moduli give a GCD, `p` and `q` that are too close give Fermat, and a factor with a smooth `p-1` gives Pollard. Padding: PKCS#1 v1.5 decryption with a distinguishable failure is the Bleichenbacher family, and its timing variant (Marvin) demonstrated that differences of single CPU cycles are detectable over a network, so any non-constant-time padding check is a finding. Signature forgery: `e=3` with a hand-rolled verifier that only compares a prefix of the padded block, or a verifier that ignores trailing data, lets an attacker compute an `e`-th root directly. The precondition for every family is the public artefacts — modulus, exponent, ciphertext or signature — plus a specific weakness in how they are used; 2048-bit RSA with OAEP and constant-time decryption is not in scope for any of them.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** two moduli share a factor **THEN** the work is a GCD and belongs to [`rsa-attacks-factorization`](../rsa-attacks-factorization/SKILL.md); it needs no lattice and no padding analysis.
2. **IF** `e` is 3 or small and the same message is encrypted to several keys **THEN** the branch is Hastad: [`rsa-attacks-small-and-low-exponent`](../rsa-attacks-small-and-low-exponent/SKILL.md).
3. **IF** a decrypt path distinguishes padding failure from content failure, in error text, status, length, or timing **THEN** the branch is [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md), and the Marvin results make timing differences alone sufficient.
4. **IF** a signature verifier parses less than the full padded block, or accepts trailing bytes **THEN** the branch is [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md).
5. **IF** the padding is OAEP and decryption is constant-time, and `e` is 65537 **THEN** none of these families apply; record the parameters as a control.
6. **IF** the modulus is below 2048 bits **THEN** report a strength finding with the factoring cost, not a specific family.
7. **IF** you are reviewing a lattice construction rather than arithmetic **THEN** switch to [`lattice-and-advanced-crypto-attacks`](../lattice-and-advanced-crypto-attacks/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `rsa-attacks-small-and-low-exponent` | [`rsa-attacks-small-and-low-exponent`](../rsa-attacks-small-and-low-exponent/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `rsa-attacks-factorization` | [`rsa-attacks-factorization`](../rsa-attacks-factorization/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `rsa-attacks-padding-oracle` | [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `rsa-attacks-signature-forgery` | [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the public parameters.** Modulus bit length, `e`, the padding scheme, and the verifier's parse depth. These four decide which family is even possible, and all four are visible without any secret.
2. **Compute the cheap checks first.** GCD across moduli, `p` and `q` proximity, and small-`e` root feasibility. These cost seconds and eliminate most of the space before any deeper work.
3. **Choose the family.** Factorisation, small exponent, padding oracle, or signature parsing. Each has its own prerequisite; mixing them produces a report that proves nothing.
4. **Define the baseline-vs-probe differential.** For factorisation: a moduli pair with a shared factor versus a coprime pair. For small exponent: a padded message versus an unpadded one under the same key. For padding: an invalid-padding ciphertext versus an invalid-content ciphertext. For signature: a full-block signature versus one with an appended byte. The differential is the acceptance or the factor, not a decrypted secret.
5. **Name the stop condition.** Stop at the first shared factor, the first integer root that verifies, the first distinguishable failure, or the first accepted malformed signature. Do not proceed to decrypt production data.
6. **State the proof.** Report the parameters, the arithmetic you performed, the artefact that verified, and the minimal change that closes it (OAEP, constant-time unpadding, full-block parsing, 2048-bit minimum). If none of the probes succeed, the disposition is `Verified Safe` with the parameters cited.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `RSA/ECB/PKCS1Padding` with a distinct catch for padding errors | Bleichenbacher family: the failure is distinguishable, which is the whole oracle | JCA, BouncyCastle, older .NET |
| `pow(m, 3)` or a raw `RSA_public_encrypt` with no padding | Small-exponent branch: an unpadded message under `e=3` is a cube root | Licence files, home-rolled crypto |
| The same modulus on two certificates | Shared-prime candidate; a GCD settles it immediately | Certificate inventory, embedded trust stores |
| `e = 65537` with `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` | Correct parameters; the finding would need a timing or parsing defect to exist at all | Modern JCA, Go `crypto/rsa` |
| A verifier that compares `decrypted[:len(expected)]` | Prefix-only comparison, so an attacker can append and adjust | Hand-written signature checks |
| A 1024-bit modulus still in service | Strength below the current floor, with a published factoring cost | Legacy TLS, firmware signing |

## Worked Contrast

**Vulnerable: PKCS#1 v1.5 decryption with distinguishable failures and a prefix-only signature check**

```java
// Two defects: a padding-specific error message (the Bleichenbacher oracle) and a
// signature check that only compares the first bytes of the recovered block.
Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
c.init(Cipher.DECRYPT_MODE, priv);
byte[] pt;
try {
    pt = c.doFinal(ct);
} catch (BadPaddingException e) {
    throw new Response(400, "padding");         // oracle
}
byte[] rec = c.doFinal(sig);
if (!Arrays.equals(Arrays.copyOf(rec, 8), EXPECTED_PREFIX)) {
    throw new Response(400, "bad signature");    // prefix-only accept
}
```

**Hardened: OAEP with one indistinguishable failure, and full-block signature verification**

```java
// OAEP removes the v1.5 padding structure; the failure is identical for every
// cause, and signature verification uses the library's full-block check.
Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
c.init(Cipher.DECRYPT_MODE, priv, new OAEPParameterSpec("SHA-256", "MGF1",
        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
byte[] pt;
try {
    pt = c.doFinal(ct);
} catch (GeneralSecurityException e) {
    throw new Response(400, "invalid request");  // one shape for all failures
}

Signature v = Signature.getInstance("RSASSA-PSS");
v.initVerify(pub);
v.update(message);
if (!v.verify(sig)) {                            // full padded-block comparison
    throw new Response(400, "invalid request");
}
```

**Why this matters:** The left handler tells the attacker exactly which failure they hit, which is one bit per query towards a full decryption, and its signature check accepts any block sharing two bytes with the expected prefix. The right handler uses OAEP so there is no padding structure to distinguish, returns one error for every cause, and delegates signature verification to a full-block check.

## When It Is NOT This Issue

- **PKCS#1 v1.5 signatures (not encryption) with full-block verification.** v1.5 signatures are still acceptable in many profiles; the Bleichenbacher family is about decryption padding.
- **A shared modulus where both keys are public and belong to the same entity.** A key rollover that reuses the modulus is a hygiene issue unless the primes differ, in which case it is a GCD finding.
- **`e=3` with OAEP and a randomised message.** Hastad needs the same unpadded message under several moduli; OAEP's randomisation defeats the broadcast.
- **A timing difference under 1 µs on a decrypt path with a 20 ms network floor.** Marvin showed small differences can be detectable, but the proof requires the statistical method, not a single measurement.
- **A 1024-bit key in an offline test fixture.** Strength findings need the key to be reachable in a deployed configuration.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `rsa-attacks` based solely on surface keywords (`e=3`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rsa-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: rsa-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-326`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`rsa-attacks-small-and-low-exponent`](../rsa-attacks-small-and-low-exponent/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-factorization`](../rsa-attacks-factorization/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rsa-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctftime (4), CYBER_CPT/L5/ctf_search (2), CYBER_CPT/github_security_md (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
