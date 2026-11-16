---
name: cryptography-design-review
description: "Reviews cryptographic design decisions: algorithm and mode selection, key lifecycle, random sources and protocol construction. Use when assessing whether crypto usage is sound by design."
family: application-security
tier: core
triggers: ["crypto design review", "cryptography review", "algorithm selection review"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Cryptography Design Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`rsa-attacks`](../../../red-team/cryptography-attacks/rsa-attacks/SKILL.md)

## Mechanism and Preconditions

A cryptography design review is about properties, not primitives: is the data confidential against the threat you named, is it authenticated so tampering is detected, is the key unique per purpose, and can you rotate it without re-encrypting the world. Most production findings are not broken algorithms but mode misuse (ECB, unauthenticated CBC), key reuse across purposes, nonces derived from something predictable, and keys stored beside the ciphertext. Encryption that cannot be rotated or authenticated is a liability with a compliance label.

- **CWE-327 (Use of a Broken or Risky Cryptographic Algorithm):** includes mode and construction misuse, not only retired algorithms; AES-128-ECB is a CWE-327 finding today.
- ASVS 5.0.0 V11 (Cryptography, 24 requirements) covers inventory, approved algorithms, randomness, and migration planning including post-quantum readiness.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the review concerns keys, their custody, or rotation mechanics **THEN** open `secrets-management-and-key-custody`; this skill judges the construction, that one judges the custody.
2. **IF** the finding is a TLS or certificate configuration **THEN** route to `zero-trust-and-mtls-service-mesh-hardening` or the TLS attack family's configuration-weakness skill.
3. **IF** the scheme is home-grown (custom composition, hand-rolled padding, XOR layering) **THEN** treat it as unauthenticated by default until a test shows tamper detection.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory every distinct use of cryptography.** Store-at-rest, transport, tokens, password hashing, integrity, and field-level encryption each have different requirements; an inventory row per use, with the primitive and mode.
2. **Check the property rather than the primitive name.** For each row: is there an authentication tag, is the nonce unique per key, is the key unique per purpose and environment, and is the algorithm appropriate for the data volume.
3. **Choose the branch on what the data must survive.** Long-lived confidentiality takes the key-rotation branch (envelope encryption, key ids per record); tamper detection takes the AEAD branch; password verification takes the KDF branch with a cost parameter tied to hardware.
4. **Define the baseline-vs-probe differential.** Baseline: encrypt and decrypt a known plaintext. Probe: flip one ciphertext byte and re-submit. A correct AEAD construction rejects; ECB or CBC without a MAC returns corrupted plaintext or an error that reveals padding.
5. **State the stop condition and the proof.** Stop when each inventory row has a named construction, a rotation path, and a passing tamper probe; proof is the probe result plus the code or config line that supplies the key and nonce.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `aes-128-ecb` or CBC without a MAC | Proves the construction is unauthenticated and pattern-revealing; identical plaintext blocks produce identical ciphertext under the same key on any stack. |
| Static IV or nonce reused across records | Proves keystream reuse for stream modes and CTR/GCM, which breaks confidentiality outright. |
| Key derived from a password with a fast hash | Proves offline guessing is cheap; the KDF must carry a memory-hard cost (Argon2id, scrypt). |
| Key version absent from the ciphertext envelope | Proves rotation requires a migration instead of a lazy re-wrap, which is why keys outlive their cryptoperiod. |

## Worked Contrast

**Vulnerable field encryption (ECB, static key, no tag, no key id):**

```python
KEY = b"notes-app-key-16"

def seal(plaintext: bytes) -> str:
    c = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return b64encode(c.update(plaintext) + c.finalize()).decode()

def open_sealed(blob: str) -> bytes:
    d = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
    return d.update(b64decode(blob)) + d.finalize()
```

**Hardened field encryption (AES-GCM, per-record nonce, key id in the envelope):**

```python
def seal(plaintext: bytes, key_id: str, aad: bytes) -> dict:
    key = kms.data_key(key_id)                 # envelope: DEK wrapped by KMS CMK
    nonce = os.urandom(12)                     # unique per record, never derived
    aes = Cipher(algorithms.AESGCM(key), modes.GCM(nonce)).encryptor()
    aes.authenticate_additional_data(aad)      # binds record id / tenant
    ct = aes.update(plaintext) + aes.finalize()
    return {"v": 1, "kid": key_id, "nonce": nonce, "ct": ct, "tag": aes.tag}

def open_sealed(env: dict, aad: bytes) -> bytes:
    key = kms.data_key(env["kid"])
    aes = Cipher(algorithms.AESGCM(key), modes.GCM(env["nonce"], env["tag"])).decryptor()
    aes.authenticate_additional_data(aad)
    return aes.update(env["ct"]) + aes.finalize()   # raises on tamper
```

**Why this matters:** The first version is deterministic, unauthenticated, and unrotatable, so a single database read reveals equality of plaintexts and a bit flip is silently decrypted. The second carries a key id and a fresh nonce per record, authenticates the record identity as associated data so ciphertexts cannot be swapped between rows, and fails closed on modification.

## When It Is NOT This Issue

- **ECB used for a single fixed block of random data.** Key wrapping with a deterministic mode over a single high-entropy block is not the same finding as ECB over structured records; check what is encrypted.
- **Unauthenticated encryption for a value that is separately MAC'd.** An HMAC over the ciphertext envelope is a valid encrypt-then-MAC construction; verify the MAC covers the nonce too.
- **AES-128 judged weak on key length alone.** 128-bit keys are approved; the finding is the mode, the key lifecycle, or the nonce discipline, not the length.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `cryptography-design-review` based solely on surface keywords (`mode selection`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cryptography-design-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: cryptography-design-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`rsa-attacks`](../../../red-team/cryptography-attacks/rsa-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cryptography-design-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 53 |
| Distinct dataset sources | 3 |
| Top sources | OffsecCyber (32), securecode-web (20), SecEval/owasp_mastg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
