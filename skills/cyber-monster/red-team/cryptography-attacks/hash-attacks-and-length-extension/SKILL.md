---
name: hash-attacks-and-length-extension
description: "Attacks hash constructions: length extension on Merkle-Damgard, collision paths, weak or truncated digests, and comparison flaws. Use when integrity or authentication relies on a bare hash."
family: cryptography-attacks
tier: core
triggers: ["hash length extension", "md5 collision", "hash bypass", "weak hash"]
cwe: [CWE-328]
owasp: []
attack: []
capec: [CAPEC-463]
related: [hash-attacks-and-length-extension-length-extension, hash-attacks-and-length-extension-collision-and-bypass, classical-and-covert-encoding, symmetric-cipher-attacks]
---

# Hash Attacks and Length Extension - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Hash function misuse splits into two independent properties. Length extension exploits the Merkle-Damgard construction: SHA-256 and SHA-512 process the message in blocks, and the final digest is the internal state after padding, so an attacker who knows `H(secret || msg)` and the length of `secret` can compute `H(secret || msg || glue_padding || suffix)` without the secret. Any MAC of the form `hash(secret || message)` is therefore forgeable, which is why HMAC exists and why `hash(key || msg)` in application code is a finding even though SHA-256 itself is unbroken. Collision attacks exploit a different property: two distinct messages with the same digest. MD5 collisions are cheap to produce and SHA-1 collisions are practical, so any signature, certificate, or integrity check that accepts them fails; the practical consequence is a chosen-prefix collision where two files with different content share an identifier. Truncation is the third failure: taking the first 8 bytes of a digest reduces preimage resistance to 64 bits and collision resistance to 32 bits, which is why truncated hashes used as identifiers need a length-appropriate threat model rather than a blanket rule.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a MAC is computed as `hash(secret || message)` or `hash(message || secret)` **THEN** it is a length-extension candidate; the secret-prefix form is directly extendable, the secret-suffix form is not but has its own problems.
2. **IF** the digest is MD5 or SHA-1 and it protects integrity, a signature, or an identifier **THEN** the collision branch applies and the finding is about what a collision lets an attacker substitute.
3. **IF** the digest is truncated below 128 bits and used as a security token **THEN** quantify the preimage and collision work before filing; a truncated hash as a cache key is not the same as one as an authenticator.
4. **IF** the code uses HMAC or a library AEAD tag **THEN** length extension does not apply and the disposition is a control; say which construction you verified.
5. **IF** the comparison of two digests uses `==` **THEN** add [`constant-time-and-crypto-side-channel-code-audit`](../constant-time-and-crypto-side-channel-code-audit/SKILL.md); the extension question and the timing question are separate.
6. **IF** the digest is used as a file-content identifier where an attacker controls both files **THEN** that is the chosen-prefix case and the strongest form of the collision finding.
7. **IF** the target is a password store **THEN** switch to [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md); fast hashes in a password path fail for a different reason.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `hash-attacks-and-length-extension-length-extension` | [`hash-attacks-and-length-extension-length-extension`](../hash-attacks-and-length-extension-length-extension/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `hash-attacks-and-length-extension-collision-and-bypass` | [`hash-attacks-and-length-extension-collision-and-bypass`](../hash-attacks-and-length-extension-collision-and-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the construction before the primitive.** Write down whether the digest is a MAC, an identifier, a signature input, or a KDF output. Only the MAC and signature cases carry the extension and collision findings; identifiers carry a substitution finding.
2. **Locate the secret's position.** For `hash(secret || msg)` compute the secret length you need — the extension proof requires `len(secret)` in bytes, which is often inferable from the format or discoverable by trying a few lengths.
3. **Choose the branch.** Extension (secret-prefix MAC), collision (MD5/SHA-1 integrity or signature), truncation (short digest as a token), or identifier substitution (attacker controls both artefacts).
4. **Define the baseline-vs-probe differential.** Baseline: a valid `(message, mac)` pair. Probe: `message || glue || suffix` with a recomputed `mac'` that uses no secret. Acceptance of the probe by the verifier is the finding, and the glue padding is fully determined by the secret length.
5. **Name the stop condition.** Stop at the first accepted extended message. Do not forge against a live production verifier; reproduce against an offline copy of the check.
6. **State the proof.** Report the construction, the secret length you assumed, the extended message's added suffix, and what the verifier does with the extra bytes (a parameter injection, a path segment, a privileged action). If the verifier rejects the probe, the disposition is `Verified Safe` with the construction that saved it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `sha256(secret + message)` used as a comparison value | Secret-prefix MAC, so extension is possible with the secret's length alone | Python/Node webhook and cookie signing |
| `md5(file_bytes)` used to decide whether two artefacts are the same | Collision-substitution: two files with different content share the digest | Package mirrors, dedup stores, update manifests |
| `sha1(cert_tbs)` accepted in a chain validator | Chosen-prefix collision enables a forged certificate body | Legacy TLS stacks, code-signing verifiers |
| `hmac.new(secret, msg, "sha256")` | Not extendable, so the construction closes the branch | Python stdlib, `node:crypto` `createHmac` |
| `digest[:8]` used as an API idempotency key | Truncation to 64 bits, so collision work is `2^32` — acceptable for idempotency, not for authenticity | Idempotency layers, short-link generation |
| A verifier that splits on the first `:` after the digest | The message boundary is attacker-movable, which is the composition failure extension turns into privilege | Custom token formats |

## Worked Contrast

**Vulnerable: secret-prefix MAC and a parse that trusts the trailing region**

```python
# sha256(secret || msg) is length-extendable: with len(secret) the attacker can
# compute sha256(secret || msg || glue || "&role=admin") without the secret.
import hashlib

def sign(msg: bytes) -> str:
    return hashlib.sha256(SECRET + msg).hexdigest()

def verify(msg: bytes, mac: str) -> dict:
    if hashlib.sha256(SECRET + msg).hexdigest() == mac:      # extendable + early exit
        return dict(p.split("=", 1) for p in msg.decode().split("&"))
    raise ValueError("bad mac")
```

**Hardened: HMAC with a length-prefixed frame and constant-time compare**

```python
# HMAC-SHA256 is not extendable, the frame declares its own length so the message
# boundary cannot move, and the compare does not exit early.
import hashlib, hmac

def sign(msg: bytes) -> str:
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()

def verify(msg: bytes, mac: str) -> dict:
    expected = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("bad mac")
    n, _, body = msg.partition(b"|")            # length prefix closes the frame
    if int(n) != len(body):
        raise ValueError("bad frame")
    return dict(p.split("=", 1) for p in body.decode().split("&"))
```

**Why this matters:** The left verifier accepts `secret || msg || glue || extra`, so an attacker appends fields to a message they were never granted and the digest still matches; the missing frame length means those appended bytes become part of the parsed claim. The right verifier uses a construction that resists extension and a frame that declares its own length, so appending anything either breaks the MAC or fails the length check.

## When It Is NOT This Issue

- **`hash(secret || msg)` where the secret is a random per-message value the attacker never observes.** Extension requires the digest of a message containing the secret; a fresh secret per message that is discarded afterwards has nothing to extend.
- **MD5 used as a non-security checksum, such as a cache key over trusted content.** Collision resistance does not matter when both inputs are produced by the same trusted process. State that trust assumption.
- **A truncated digest used for sharding or idempotency.** 64 bits of an idempotency key is a collision-probability question, not an authenticity question.
- **HMAC compared with a length check first.** The length of a tag format is public, so the early length comparison leaks nothing about the secret.
- **A SHA-1 digest in a historical migration script that only reads.** The validator no longer accepts it; the digest is data, not a control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `hash-attacks-and-length-extension` based solely on surface keywords (`length extension`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hash-attacks-and-length-extension` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: hash-attacks-and-length-extension
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-328`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`hash-attacks-and-length-extension-length-extension`](../hash-attacks-and-length-extension-length-extension/SKILL.md) - Cryptography Attacks (leaf)
- [`hash-attacks-and-length-extension-collision-and-bypass`](../hash-attacks-and-length-extension-collision-and-bypass/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hash-attacks-and-length-extension` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-328`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/ctftime (3), CYBER_CPT/hacktricks (2), SecEval/cs161_textbook (1), hackerone_disclosed_reports (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
