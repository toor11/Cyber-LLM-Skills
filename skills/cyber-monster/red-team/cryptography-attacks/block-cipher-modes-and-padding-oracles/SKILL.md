---
name: block-cipher-modes-and-padding-oracles
description: "Exploits block cipher mode misuse: ECB pattern leakage, CBC bit flipping, padding oracle decryption, and IV and salt handling errors. Use when block encryption output is observable or decryptable by the attacker."
family: cryptography-attacks
tier: core
triggers: ["padding oracle", "cbc bit flip", "ecb oracle", "block cipher mode attack"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation, block-cipher-modes-and-padding-oracles-cbc-bit-flipping, block-cipher-padding-oracle-exploitation, classical-and-covert-encoding]
---

# Block Cipher Modes and Padding Oracles - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Block cipher mode misuse is the family of defects that appear when a keyed permutation is turned into a message cipher without an integrity bound. ECB encrypts each 16-byte block independently, so equal plaintext blocks produce equal ciphertext blocks and the ciphertext becomes a substitution alphabet over a 16-byte alphabet; a reordered or duplicated block still decrypts. CBC chains blocks with `C[i] = E(P[i] xor C[i-1])`, which makes the ciphertext malleable: flipping bit `j` of `C[i-1]` flips the same bit in `P[i]` while corrupting `P[i-1]` into noise the attacker can often absorb in a field they do not control. Padding oracle attacks need one more ingredient — a distinguishable failure mode for "bad padding" versus "bad plaintext" — because PKCS#7 unpad reveals one bit of the decrypted last block per query, and around 128 queries per byte recover the block. The precondition that binds all three is that the attacker can observe ciphertext and either reorder blocks, submit modified ciphertext for decryption, or read a length or error that differs between padding failure and downstream failure.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** identical plaintext blocks produce identical ciphertext blocks in a sample you encrypted yourself **THEN** take the ECB branch: [`block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation`](../block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation/SKILL.md).
2. **IF** the ciphertext decrypts under a modified preceding block and the target field is in the block after it **THEN** take the malleability branch: [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](../block-cipher-modes-and-padding-oracles-cbc-bit-flipping/SKILL.md).
3. **IF** decryption reports padding failure differently from content failure (status code, error string, timing, or a different follow-on message) **THEN** take the oracle branch: [`block-cipher-padding-oracle-exploitation`](../block-cipher-padding-oracle-exploitation/SKILL.md).
4. **IF** the ciphertext is authenticated by a MAC computed over the whole message with a separate key **THEN** stop at this skill: a correct encrypt-then-MAC construction removes the malleability and the oracle, and the finding is a non-finding with a note on the ordering.
5. **IF** the mode is CBC but the IV is a fixed constant **THEN** treat it as both an equality leak (same first block) and a chosen-prefix lever, not as a padding issue.
6. **IF** the code is a stream construction (CTR, OFB, CFB, GCM) **THEN** switch to [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](../symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md); the block-boundary arithmetic does not apply.
7. **IF** the review is about which primitive or mode to standardise on **THEN** start at [`crypto-implementation-review`](../crypto-implementation-review/SKILL.md) and return here only for a concrete defect.
8. **IF** the plaintext is a single block or shorter than one block **THEN** **STOP**: ECB and CBC chaining defects need at least two blocks to show, so the disposition is `Not Applicable` rather than a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation` | [`block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation`](../block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `block-cipher-modes-and-padding-oracles-cbc-bit-flipping` | [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](../block-cipher-modes-and-padding-oracles-cbc-bit-flipping/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `block-cipher-padding-oracle-exploitation` | [`block-cipher-padding-oracle-exploitation`](../block-cipher-padding-oracle-exploitation/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the block geometry first.** Read the mode, the block size, and whether the code pads with PKCS#7, zero-pads, or uses ciphertext stealing. Write down `len(ciphertext)` against `len(plaintext)` for one known input; the delta is the padding length and it tells you which oracle you can even reach.
2. **Locate the observable channel.** For ECB and CBC that is the ciphertext itself. For the oracle it is whatever the caller sees on a failed unpad: an HTTP status, a distinct error code, a log line the caller can trigger, or a measurable time gap. If no channel reaches an untrusted party, there is no oracle and the finding drops to a code-quality note.
3. **Choose the branch and its arithmetic.** ECB: count repeated 16-byte blocks at 2, 3, and 4 identical plaintext lengths and look for the jump from 2 to 3. CBC flip: compute which ciphertext block precedes the field you want to change. Padding oracle: note that each block needs about 128 queries to resolve a byte through the padding-length signal.
4. **Establish the baseline-vs-probe differential.** Baseline is the untouched ciphertext. Probe is the same ciphertext with one deliberate bit flipped in the preceding block, or one byte appended. A correct AEAD rejects both; a vulnerable path returns either a decrypt with a corrupted neighbour block or a padding-specific error.
5. **Name the stop condition.** Stop when you have one accepted modified ciphertext (malleability), one repeated-block pair (ECB), or two distinguishable failure messages (oracle). Do not iterate a full recovery to prove the point.
6. **State the proof.** The finding is: mode and padding, the exact bit or byte you changed, the observable difference against the baseline, and what the difference lets an attacker conclude. If the probe is rejected with the same error and the same timing as the baseline, record `Verified Safe` and name the MAC or AEAD that produced the rejection.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Three identical 16-byte plaintext prefixes produce three identical ciphertext prefixes | ECB, and a substitution alphabet the attacker can permute across accounts | Java `Cipher.getInstance("AES/ECB/PKCS5Padding")`, OpenSSL `aes-256-ecb` |
| `Cipher.getInstance("AES/CBC/PKCS5Padding")` with no adjacent `Mac` call | CBC without integrity, so the malleability branch is open even if no oracle exists | JCA, `node:crypto` `createCipheriv('aes-128-cbc')` |
| A 500 on `unpad` and a 401 on bad credentials in the same handler | Two distinguishable failures, which is the whole precondition for a padding oracle | Web frameworks that catch `BadPaddingException` separately |
| `pad(unpad(x))` round-trip in a test asserting "invalid padding throws" | The library exposes padding validity to the caller, so timing or error text can escape | Python `cryptography`, PyCryptodome `Crypto.Util.Padding` |
| IV stored as a literal `b'\x00'*16` or a constant | Fixed IV makes the first block deterministic, proving an equality leak independent of padding | Any CBC call site with a module-level IV |
| `AES/GCM/NoPadding` with a full tag on the same payload | Encrypt-then-MAC equivalent, which closes both branches; belongs in non-findings | JCA GCM, BoringSSL EVP AEAD |

## Worked Contrast

**Vulnerable: CBC with a fixed IV, no MAC, and a padding error that reaches the caller**

```java
// AES/CBC with a constant IV: block 1 is deterministic, and nothing authenticates
// the ciphertext, so any bit of C[i-1] can be flipped to steer P[i].
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
try {
    return c.doFinal(ciphertext);
} catch (BadPaddingException e) {
    throw new Response(400, "bad padding");   // distinguishable failure = oracle
} catch (IllegalBlockSizeException e) {
    throw new Response(400, "bad length");
}
```

**Hardened: AEAD with a canonical AAD and one indistinguishable failure path**

```java
// One construction carries confidentiality and integrity; the caller learns only
// "rejected", and the AAD binds the ciphertext to the record it belongs to.
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(128, nonce));
c.updateAAD(("v1|tenant=" + tenantId + "|rec=" + recordId).getBytes(UTF_8));
try {
    return c.doFinal(blob);            // full 128-bit tag verified here
} catch (AEADBadTagException e) {
    throw new Response(400, "invalid request");  // same shape for every failure
}
```

**Why this matters:** The left handler lets an attacker flip a chosen bit in one plaintext block at the cost of scrambling the previous one, and hands them a padding-specific error that turns decryption into a per-byte guessing game. The right handler authenticates before it decrypts and returns one indistinguishable rejection, so a modified ciphertext yields no information at all and no error channel to build an oracle on.

## When It Is NOT This Issue

- **CBC inside an encrypt-then-MAC envelope.** If a MAC over `IV || ciphertext` is verified before any unpad, bit-flipping is detected and the padding branch is unreachable. Confirm the verification order in code, not in the design doc.
- **A padding error that is mapped to the same generic response as every other failure.** Distinguishability is the precondition; a uniform 400 with a uniform body and no length change removes the oracle even when the code throws on bad padding internally.
- **ECB over a single block, or over random data.** ECB's equality leak needs repeated plaintext structure. Encrypting one 16-byte key wrap or a random nonce with ECB is ugly but not a finding.
- **A CBC IV that is random per message but reused across a retry of the same message.** Retry determinism leaks equality of two ciphertexts the attacker already knows are the same plaintext; that is not a confidentiality break.
- **`BadPaddingException` thrown but never returned to the caller.** Test harnesses, offline decryptors, and admin-only CLIs that surface padding errors are outside the attacker's channel.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `block-cipher-modes-and-padding-oracles` based solely on surface keywords (`ECB cut and paste`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `block-cipher-modes-and-padding-oracles` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: block-cipher-modes-and-padding-oracles
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation`](../block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation/SKILL.md) - Cryptography Attacks (leaf)
- [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](../block-cipher-modes-and-padding-oracles-cbc-bit-flipping/SKILL.md) - Cryptography Attacks (leaf)
- [`block-cipher-padding-oracle-exploitation`](../block-cipher-padding-oracle-exploitation/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `block-cipher-modes-and-padding-oracles` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (3), SecEval/owasp_wstg (1), hackerone_disclosed_reports (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
