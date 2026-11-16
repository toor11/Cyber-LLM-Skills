---
name: aead-aes-gcm-and-chacha20-misuse
description: "Audits Authenticated Encryption with Associated Data (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, XChaCha20) implementations: 96-bit nonce reuse / birthday collisions (`N^2 / 2^97` -> GHASH key `H` recovery forbidden attack), truncated GCM authentication tags outside NIST SP 800-38D `{128,120,112,104,96}`-bit minimums, missing AAD context binding (`tenant_id`/`record_id` cross-tenant ciphertext transplant), and chunked stream AAD sequence/finality checks. Use when reviewing modern AEAD encryption code."
family: cryptography-attacks
tier: core
triggers: ["aes-gcm nonce reuse", "forbidden attack gcm", "truncated gcm tag", "missing aad binding", "chacha20 poly1305"]
cwe: [CWE-323, CWE-354, CWE-345]
owasp: []
attack: []
capec: []
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
corpus_sparse: true
---

# AEAD Aes GCM and Chacha20 Misuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

AEAD misuse is a construction-level defect, not a primitive break. AES-GCM derives its CTR keystream from `(K, J0)` and authenticates with GHASH under a key `H = E_K(0^128)`. Two Encrypt calls under the same key and 96-bit nonce XOR the same keystream, so `C1 xor C2 = P1 xor P2` leaks plaintext structure, and the pair also yields two GHASH evaluations of the same `H`, which is enough to solve the polynomial over `GF(2^128)` and recover `H` — the "forbidden attack" — after which tags are forgeable for any ciphertext under that key. NIST SP 800-38D §5.2.1.2 permits tag lengths `t ∈ {128, 120, 112, 104, 96}` bits; anything shorter, or a tag compared with `==` instead of a constant-time compare, converts authentication into an online guessing game bounded by `2^-t`. The third defect is scope: AAD that omits the record's identity lets a ciphertext be transplanted between tenants, records, or columns and still verify, because the tag only proves "some key holder produced this", not "this belongs here". ChaCha20-Poly1305 moves the nonce to 96 bits too (192 with XChaCha20), and its Poly1305 one-time key is likewise a function of `(K, nonce)`, so the same reuse and AAD-scope reasoning applies.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the construction is AES-GCM or ChaCha20-Poly1305 and the nonce is random per message under a long-lived key **THEN** compute the message budget `2^32` for 96-bit nonces and check whether a per-record DEK, a persisted counter, or AES-GCM-SIV (RFC 8452) bounds it.
2. **IF** the tag length in code is below 96 bits, or the tag is sliced (`ct[:-12]`, `ct[16:]`) **THEN** treat it as a forgerable tag and quantify the online attempts the profile still allows before calling it exploitable.
3. **IF** `associated_data` is `None` or a constant **THEN** trace whether `tenant_id`, `record_id`, and `key_version` reach the AAD; absent them, the finding is ciphertext transplant, not decryption.
4. **IF** the plaintext is chunked or streamed **THEN** check that per-chunk AAD carries `(stream_id, chunk_index, is_final)`; without `is_final` a truncated stream verifies.
5. **IF** the work is a design review of a new envelope format **THEN** start at [`envelope-encryption-and-kms-tenant-isolation`](../envelope-encryption-and-kms-tenant-isolation/SKILL.md) for KEK/DEK custody, then return here for the AEAD parameters.
6. **IF** the code compares tags, MACs, or KDF outputs with `==` **THEN** switch to [`constant-time-and-crypto-side-channel-code-audit`](../constant-time-and-crypto-side-channel-code-audit/SKILL.md); timing is a different proof obligation.
7. **IF** you need the blue-team disposition **THEN** pivot to [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md).
8. **IF** no call site constructs a nonce, tag length, or AAD at all **THEN** **STOP**: the pattern is absent, and the correct output is a non-finding, not a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the sink.** Find the single call that produces or consumes the AEAD output (`AESGCM.encrypt`, `aead.Seal`, `EVP_EncryptFinal_ex` with a GCM cipher). Record the file, the function, and whether the output crosses a trust boundary (stored, sent, or returned to a caller with a different tenant).
2. **Enumerate the four parameters from the call site, not the docs.** Nonce source and width, tag length actually carried in the output buffer, AAD expression, and key lifetime in messages. A parameter you cannot read from code is a parameter you must mark unknown rather than assume safe.
3. **Choose the branch.** Reuse branch (counter or RNG budget exceeded, or a static IV), truncation branch (tag `< 96` bits or sliced), or scope branch (AAD missing record identity). Each branch has its own proof; do not merge them into one finding.
4. **Build the baseline-vs-probe differential.** Baseline: encrypt the same plaintext twice under a fresh key and confirm two distinct nonces and two distinct ciphertexts. Probe: encrypt twice with the recorded nonce path and diff. Identical leading ciphertext blocks, or a nonce counter that repeats inside the sample, is the evidence. For the scope branch, probe by decrypting a ciphertext under a different `record_id` and observing whether it verifies.
5. **Name the stop condition before you run anything.** Stop at the first repeat of `(key, nonce)` in an offline sample, or at the first ciphertext that verifies under a foreign AAD. Do not escalate to recovering `H` or decrypting production data — the repeat is already the finding.
6. **State the proof.** A finding needs: the call site, the parameter that violates the invariant, the number of messages the deployment would need to reach the birthday bound, and the concrete consequence (plaintext XOR leak, tag forgery, cross-tenant transplant). Absent a reachable call site with a violating parameter, the disposition is `Verified Safe` with the reason recorded.

## Concrete Patterns

| Indicator in code or config | What it proves | Stack / surface |
|---|---|---|
| `nonce = os.urandom(12)` under a single long-lived `kek` | Random 96-bit nonces cap the safe message count near `2^32` per key; proves a key-lifetime defect, not a present collision | Python `cryptography` `AESGCM`, Go `cipher.AEAD`, JCA `GCMParameterSpec` |
| `ct[:-12]` or `tag[:4]` in the encode path | The stored tag is shorter than the 96-bit floor, so the forger's search space is `2^(8*len)` and offline verification is a loop | Any AEAD wrapper that serialises `nonce  then  ct  then  tag` by hand |
| `associated_data=None` on a per-tenant record | Tag verifies regardless of owner, so a row moved between tenants still authenticates: broken scope, not broken crypto | ORM field encryptors, KMS-adjacent envelope helpers |
| `AESGCM(dek).encrypt(..., aad)` with `dek` regenerated per record | Per-record key plus full tag removes the birthday bound; proves the reuse branch is already mitigated and belongs in non-findings | Service-layer encryptors, per-object DEK patterns |
| `crypto.subtle.decrypt({name:"AES-GCM", tagLength:32})` | A 32-bit `tagLength` is outside the SP 800-38D general set; proves an online-forgery budget of roughly `2^32` attempts | WebCrypto in browsers and Node `webcrypto` |
| `XChaCha20-Poly1305` with 192-bit random nonce | Wide random nonce makes collision negligible at practical volumes; proves the nonce branch is closed while AAD scope still needs checking | libsodium `crypto_aead_xchacha20poly1305_ietf`, `@noble/ciphers` |

## Worked Contrast

**Vulnerable: static key, random nonce, sliced tag, no AAD binding**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def seal_row(kek: bytes, tenant_id: str, row: bytes) -> bytes:
    # The nonce is random but the KEY never rotates: at ~2^32 rows the birthday
    # bound for 96-bit nonces is reached and a repeat XORs out the keystream.
    nonce = os.urandom(12)
    # associated_data omitted => a row copied to another tenant still verifies.
    blob = AESGCM(kek).encrypt(nonce, row, None)
    # Tag sliced to 4 bytes: 2^32 online forgeries instead of 2^128.
    return nonce + blob[:-12]
```

**Hardened: per-record DEK, full tag, canonical AAD carrying identity and version**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def seal_row(kek: bytes, tenant_id: str, row_id: str, kv: int, row: bytes) -> dict:
    # Fresh DEK per record: the (key, nonce) pair can never repeat across rows.
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    # Length-prefixed AAD makes "belongs to this tenant and version" part of the tag.
    aad = f"v1|t={len(tenant_id)}:{tenant_id}|r={len(row_id)}:{row_id}|kv={kv}".encode()
    blob = AESGCM(dek).encrypt(nonce, row, aad)  # 16-byte tag, never sliced
    return {"wrapped_dek": wrap(kek, dek, aad), "nonce": nonce, "blob": blob}
```

**Why this matters:** The left version has three independent defects that each break a different property — keystream reuse destroys confidentiality at scale, the 4-byte tag destroys integrity against an online attacker, and the empty AAD destroys tenant isolation without touching the key at all. The right version closes reuse with a per-record key, keeps the full 128-bit tag so forgery stays at `2^-128`, and makes identity part of the authenticated data so a transplanted row fails verification instead of silently succeeding.

## When It Is NOT This Issue

- **Random 96-bit nonce under a key that is provably per-message or per-record.** If the key is regenerated (or derived with a counter) for every message, the birthday bound never binds and the random nonce is correct. Confirm the key lifecycle before filing.
- **A short tag that is an inner layer, not the outer one.** Some formats carry a 32-bit tag inside a frame that is itself inside TLS with a full-strength MAC. The inner tag is a corruption check; flagging it as a forgery primitive without showing the outer layer is missing is a false positive.
- **`associated_data=None` where the ciphertext never leaves its row.** If the blob is stored in the same row as the tenant key and every read re-reads that row, transplant requires database write access that already grants the plaintext. Say so in *Verified Safe* rather than filing a scope bug.
- **GCM-SIV or a nonce-misuse-resistant mode with a repeated nonce.** AES-GCM-SIV derives its key from the nonce, so a repeat degrades to deterministic encryption rather than keystream reuse. It leaks equality, not plaintext.
- **A tag comparison in a unit test or CLI verifier.** Test fixtures and offline audit tools that use `==` are not reachable by a network attacker; timing there proves nothing about the service.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `aead-aes-gcm-and-chacha20-misuse` based solely on surface keywords (`AES-GCM 96-bit nonce`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `aead-aes-gcm-and-chacha20-misuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: aead-aes-gcm-and-chacha20-misuse
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-323, CWE-354, CWE-345`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `aead-aes-gcm-and-chacha20-misuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-323, CWE-354, CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
