---
name: symmetric-cipher-attacks-weak-key-derivation
description: Weak symmetric key derivation. Covers predictable keys from weak KDFs, password-to-key shortcuts and key reuse across contexts. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["weak kdf", "predictable key", "key derivation weakness"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [symmetric-cipher-attacks, symmetric-cipher-attacks-keystream-and-nonce-reuse, classical-and-covert-encoding, block-cipher-modes-and-padding-oracles]
parent: symmetric-cipher-attacks
corpus_sparse: true
---

# Symmetric Cipher Attacks Weak Key Derivation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Weak key derivation is the case where the cipher is sound and the key is guessable. The direct forms are a key literal in source, a key derived by padding or truncating a passphrase (`key = password.ljust(32, b"\0")`), a key from a hash of a short secret with no work factor, and a key shared between environments because it was generated once and copied. The measurable consequence is a search space: `hash(passphrase)` inherits the passphrase's entropy, so a 20-bit human choice stays 20 bits no matter how the hash looks, and a GPU covers that space in seconds. The subtler forms are derivation without a salt (identical passphrases give identical keys, so one crack covers many deployments) and derivation with a fast KDF where the parameter is the only defence (PBKDF2 at 1000 iterations is roughly a thousand times cheaper to attack than at 600000). The review question is not "is AES used" but "what is the entropy of the actual key material, and how many guesses does an attacker need per candidate". Two operational defects belong here too: a key that never rotates, and a key that is the same across tenants, both of which concentrate a single compromise.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the key is a literal, a padded passphrase, or a hash of a short string **THEN** estimate the entropy of the source and the guesses per candidate; that ratio is the finding.
2. **IF** the KDF is PBKDF2, scrypt, or Argon2id **THEN** read the parameters from the derivation call and compare against a current floor; record the numbers, not the algorithm name.
3. **IF** the derivation has no salt **THEN** the finding is cross-deployment equality, which is independent of the entropy.
4. **IF** the same key appears in more than one environment, tenant, or service **THEN** that is a blast-radius finding; the fix is separation, not a stronger cipher.
5. **IF** the key comes from a KMS or an HSM and never appears in the process **THEN** the disposition is a control; record the custody boundary.
6. **IF** the review is about a nonce or counter defect **THEN** switch to [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md).
7. **IF** the derived value protects a password **THEN** switch to [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md); the threat model is different.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Trace the key to its origin.** From the `Cipher` call backwards to the literal, environment variable, KMS call, or derivation function. A key whose origin cannot be named is itself a finding.
2. **Estimate the source entropy.** A random 32-byte key is 256 bits; a passphrase from a human is tens of bits at best. Do not infer entropy from the length of the derived key.
3. **Choose the branch.** Literal key (source-code exposure), weak derivation (KDF or no KDF), shared key (blast radius), or unrotated key (lifetime). Each has a different fix.
4. **Define the baseline-vs-probe differential.** Baseline: derive the key from the documented secret and confirm it matches the deployment's. Probe: derive it from a dictionary candidate and measure how many candidates per second the derivation permits. The rate, multiplied by the candidate space, is the proof.
5. **Name the stop condition.** Stop at the measured derivation rate plus the entropy estimate. Do not crack the key.
6. **State the proof.** Report the key's origin, the entropy estimate with its basis, the derivation cost per candidate, the resulting search time, and the rotation or KMS fix. If the key is KMS-held and per-tenant, record `Verified Safe` with the custody detail.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `KEY = b"changeme-changeme-changeme-changeme"` | Literal key in source, so anyone with repository access holds it | Application config, container images |
| `key = password.encode().ljust(32, b"\0")` | Entropy of the passphrase, plus a structured tail that narrows the search further | Legacy file encryption |
| `hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)` | Work factor a thousand times below a current floor, so offline search is cheap | Older Django, hand-rolled KDFs |
| `hashlib.sha256(passphrase).digest()` used directly as a key | No work factor at all, so GPU rate applies to the passphrase space | Home-rolled encryption helpers |
| `kms.generate_data_key` per record, DEK never persisted | Correct custody: the key never lives in source and is per-object | Modern envelope encryption |
| One `ENCRYPTION_KEY` env var shared by every service | Blast radius: one leak compromises every service and every tenant | Shared configuration management |

## Worked Contrast

**Vulnerable: key derived by hashing a passphrase with no work factor or salt**

```python
# The key's entropy is the passphrase's entropy. sha256 is fast, so a GPU walks a
# human-chosen space in minutes, and no salt means the same passphrase gives the
# same key in every deployment.
import hashlib
from Crypto.Cipher import AES

PASSPHRASE = "company-secret-2024"

def key_from_passphrase() -> bytes:
    return hashlib.sha256(PASSPHRASE.encode()).digest()      # no salt, no KDF

def encrypt(plaintext: bytes) -> bytes:
    return AES.new(key_from_passphrase(), AES.MODE_GCM).encrypt(plaintext)
```

**Hardened: a random key held by KMS, or a salted memory-hard derivation as fallback**

```python
# Primary path: a per-tenant random DEK from KMS, which never derives from a
# human secret. Fallback path: Argon2id with a stored salt and tuned parameters.
import os
from argon2.low_level import hash_secret_raw, Type

def key_from_kms(kms, tenant_kek: str) -> bytes:
    return kms.generate_data_key(KeyId=tenant_kek, KeySpec="AES_256")["Plaintext"]

def key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(passphrase.encode(), salt, time_cost=3,
                           memory_cost=65536, parallelism=4,
                           hash_len=32, type=Type.ID)
```

**Why this matters:** The left key is exactly as strong as an eight-word human phrase and no stronger, because the hash adds no work and the missing salt means one crack covers every deployment. The right path either removes the human secret entirely by taking a random key from KMS, or makes each guess cost 64 MiB and three passes with a per-deployment salt, which raises the attacker's cost by the same factor.

## When It Is NOT This Issue

- **A key in a test fixture or a docker-compose sample.** Not deployed; confirm the file is excluded from production configuration.
- **A passphrase-derived key with Argon2id at current parameters and a per-deployment salt.** The derivation is the defence, and it is present.
- **A short key for a non-security purpose, such as cache-key hashing.** No confidentiality claim, so entropy does not matter.
- **An environment variable holding a 32-byte random value from a secret manager.** The variable is the transport, not the origin; check the manager, not the variable.
- **A key shared between a service and its own sidecar with no other consumer.** Single-tenant, single-purpose; note it, but the blast radius argument does not apply.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `symmetric-cipher-attacks-weak-key-derivation` based solely on surface keywords (`weak KDF`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `symmetric-cipher-attacks-weak-key-derivation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: symmetric-cipher-attacks-weak-key-derivation
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](../symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `symmetric-cipher-attacks-weak-key-derivation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
