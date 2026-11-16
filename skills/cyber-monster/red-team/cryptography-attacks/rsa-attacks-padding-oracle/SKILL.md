---
name: rsa-attacks-padding-oracle
description: RSA padding oracle attacks. Covers Bleichenbacher and PKCS#1 v1.5 oracle attacks against RSA padding, and the timing behaviour that enables them. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["bleichenbacher", "rsa padding oracle", "pkcs1 oracle"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-463]
related: [rsa-attacks, rsa-attacks-small-and-low-exponent, rsa-attacks-factorization, rsa-attacks-signature-forgery]
parent: rsa-attacks
---

# Rsa Attacks Padding Oracle - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

The RSA padding oracle is Bleichenbacher's 1998 result made practical again by timing. A PKCS#1 v1.5 ciphertext decrypts to `0x00 0x02 || PS || 0x00 || M`, and the decoder rejects the block unless the leading bytes match, the separator exists, and `PS` is at least eight non-zero bytes. That rejection is one bit of information about `D(c)`. The original attack multiplies the ciphertext by `s^e` for chosen `s`, which multiplies the plaintext by `s`, and narrows an interval for `m` with each query that reports "the padding was valid" — around a million queries for a 1024-bit key naively, far fewer with the optimisations in the literature and with the Manger variant against OAEP. The Marvin work is the part that matters for modern review: it showed that differences as small as a single CPU cycle can be detected over a network with the right statistical method, so "we return the same error message" is not sufficient; the decryption must be constant-time, which in OpenSSL means the implicit-rejection changes and in application code means never branching on the padding result. The precondition is a decrypt path reachable with attacker-chosen ciphertext, under a key whose plaintext matters, with any observable difference at all.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the path is RSA decryption with PKCS#1 v1.5 padding **THEN** it is in scope regardless of what the error message says; the question is only whether timing or another channel distinguishes the failures.
2. **IF** the padding is OAEP **THEN** Manger's attack applies to the "is the leading byte zero" distinction; the arithmetic differs but the observable discipline is the same.
3. **IF** the only difference is timing **THEN** require a statistical proof with a stated sample size and double-blind ordering before claiming an oracle.
4. **IF** the protocol is TLS with `ECDHE_RSA` suites **THEN** there is no RSA decryption padding to oracle — the RSA operation is a signature, not a decryption. This is the most common false positive.
5. **IF** the library version includes the constant-time implicit-rejection fixes **THEN** record the version as the control and note that application code can still reintroduce a branch.
6. **IF** the ciphertext is decrypted once and the result is discarded on failure, with the same timing and the same response **THEN** the disposition is `Verified Safe`; say which version and which code path.
7. **IF** the target is a CBC symmetric padding oracle **THEN** switch to [`block-cipher-padding-oracle-exploitation`](../block-cipher-padding-oracle-exploitation/SKILL.md).

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

1. **Confirm the operation is decryption, not verification.** RSA in TLS 1.3 and in all `ECDHE_RSA` suites is used for signatures. A padding oracle requires the private key applied to attacker-supplied ciphertext, which in practice means PKCS#1 v1.5 key transport, a licence or envelope format, or an application "decrypt this blob" endpoint.
2. **Identify the failure channel.** Error text, error code, response length, response time, or a downstream behaviour that differs (a retry, a redirect, a different next step). Enumerate all of them before concluding there is none.
3. **Check the library's constant-time status.** For OpenSSL, the implicit-rejection work changed the decryption API so that a padding failure returns a random-looking plaintext rather than an error. Older versions and some language bindings bypass it.
4. **Define the baseline-vs-probe differential.** Baseline: a ciphertext known to have valid padding, and one known to be invalid. Probe: many repetitions of each, in randomised order, measuring the observable. A statistically significant shift with a stated sample size is the finding; a categorical difference is a stronger finding.
5. **Name the stop condition.** Stop at a proven channel, not at a decryption. Report the queries-per-bit estimate from the literature rather than performing the attack.
6. **State the proof.** Report the operation, the padding scheme, the channel, the measurement with its noise floor, and the remediation (OAEP, constant-time decryption, or removal of the decrypt path). If no channel exists, name the control that closed it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `RSA/ECB/PKCS1Padding` in a decrypt call | The v1.5 padding structure exists, so the oracle is possible if any channel leaks | JCA, BouncyCastle, .NET `RSACryptoServiceProvider` |
| A catch block that maps `BadPaddingException` to its own response | Categorical oracle, the strongest form | Web handlers, RPC frameworks |
| `RSA_private_decrypt` with `RSA_PKCS1_PADDING` in C | Version-dependent constant-time status; pre-fix builds leak through timing | OpenSSL bindings, firmware |
| `RSA/ECB/OAEPWithSHA-1AndMGF1Padding` on a current library | OAEP is not immune to Manger, but the v1.5 structure is gone; check the leading-byte distinction | Modern JCA, Go `crypto/rsa` |
| `ECDHE_RSA` in a TLS 1.3 handshake | RSA is used for signing only, so this class does not apply — the common false positive | Any TLS 1.3 stack |
| Decryption that returns a random plaintext on padding failure | Implicit rejection, which removes the oracle by construction | OpenSSL 3.2+ with `rsa_pkcs1_implicit_rejection` |

## Worked Contrast

**Vulnerable: decrypt endpoint that branches on padding validity and reports it**

```python
# PKCS#1 v1.5 decryption where the padding failure is a distinct HTTP response.
# One bit per query is all Bleichenbacher needs.
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def unwrap(ct: bytes) -> bytes:
    try:
        return PRIV.decrypt(ct, padding.PKCS1v15())
    except ValueError:
        raise HTTPError(400, "padding")      # the oracle, verbatim
```

**Hardened: OAEP with one indistinguishable failure and no branch on the plaintext**

```python
# OAEP removes the v1.5 structure, and every failure returns the same response
# shape so no channel distinguishes a padding problem from any other cause.
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)

def unwrap(ct: bytes) -> bytes:
    try:
        return PRIV.decrypt(ct, OAEP)
    except ValueError:
        raise HTTPError(400, "invalid request")   # identical for every cause
```

**Why this matters:** The left handler answers the attacker's question — was the padding right — which is exactly the one bit Bleichenbacher's interval narrowing consumes per query. The right handler uses OAEP so there is no v1.5 structure to report on, and funnels every failure into one response so neither the error text nor the length reveals which check failed.

## When It Is NOT This Issue

- **RSA used for signatures, including every `ECDHE_RSA` TLS suite and every TLS 1.3 handshake.** No private-key decryption of attacker data happens, so there is nothing to oracle.
- **A decrypt endpoint reachable only by the key's owner.** The oracle needs an attacker-chosen ciphertext under someone else's key.
- **A library on a version with implicit rejection, called without application-level branching.** The decryption API itself returns a pseudo-random plaintext on padding failure; the control is real and should be cited.
- **A timing difference smaller than the measured noise floor across a double-blind sample.** This is the most common over-claim; report the measurement and the floor.
- **PKCS#1 v1.5 encryption used only for key wrapping inside a trusted process.** No attacker-chosen ciphertext, no oracle.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `rsa-attacks-padding-oracle` based solely on surface keywords (`Bleichenbacher`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rsa-attacks-padding-oracle` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: rsa-attacks-padding-oracle
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
- [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rsa-attacks-padding-oracle` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/github_security_md (6), CYBER_CPT/ctftime (2), CYBER_CPT/ctf_wiki (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
