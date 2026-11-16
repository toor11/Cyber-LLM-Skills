---
name: block-cipher-modes-and-padding-oracles-cbc-bit-flipping
description: CBC bit flipping and IV manipulation. Covers flipping ciphertext and IV bits to alter decrypted plaintext predictably, including first-block and prefix control. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["cbc bit flip", "iv manipulation", "bit flipping attack"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [block-cipher-modes-and-padding-oracles, block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation, block-cipher-padding-oracle-exploitation, classical-and-covert-encoding]
parent: block-cipher-modes-and-padding-oracles
corpus_sparse: true
---

# Block Cipher Modes and Padding Oracles CBC Bit Flipping - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

CBC bit flipping exploits the decryption equation rather than the padding. Decryption computes `P[i] = D(C[i]) xor C[i-1]`, so modifying bit `j` of `C[i-1]` modifies bit `j` of `P[i]` with probability one and leaves every other plaintext block untouched, while `P[i-1]` becomes unpredictable noise. The attacker therefore needs a plaintext layout where the block they corrupt is one they do not care about, or one they can restore, and a target field that lives in the following block. The classic case is a serialised permission blob or a cookie of the form `uid=...;role=user;` where `admin` and `user` differ by bits in a known position: 8-16 bytes of ciphertext arithmetic convert `user` to `admin` without the key. The variant that matters for review is the IV: `P[0] = D(C[0]) xor IV`, so a controllable IV gives the same lever on the first block with no collateral corruption at all, which turns a "needs one sacrificial block" attack into a clean single-bit edit. The precondition is unauthenticated CBC plus a plaintext format whose field offsets are discoverable, which in practice means the format is JSON, a query string, or a fixed-width record.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the IV reaches the client (a parameter, a cookie, or the first block of the blob) **THEN** take the IV branch: the first plaintext block is editable with no collateral damage, which is the cleanest proof you can produce.
2. **IF** the target field is not in block 0 **THEN** check whether the preceding block is padding, a free-text field, or something you can re-supply; if none of those, the branch needs a format change to be reachable.
3. **IF** the plaintext format is JSON **THEN** a flipped byte usually breaks parsing before it changes a value; measure the parse-failure response instead of assuming success.
4. **IF** a MAC covers the ciphertext **THEN** stop: this skill's lever is closed, and the finding is the non-finding plus the verification order.
5. **IF** the target is a stream cipher or CTR **THEN** switch to [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](../symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md); there is no chaining to steer.
6. **IF** the field you want to change sits in the corrupted block rather than the next one **THEN** the attack is not bit flipping but IV control, and you should re-derive the offsets.
7. **IF** you need the padding-failure variant of CBC misuse **THEN** switch to [`block-cipher-padding-oracle-exploitation`](../block-cipher-padding-oracle-exploitation/SKILL.md); the observable is different.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Recover the plaintext layout.** You need the byte offset of the field you intend to change and the offset of the block before it. For a format you control, encrypt a known plaintext yourself; for an opaque blob, use length deltas and a decrypt endpoint that echoes structure.
2. **Confirm the chaining lever.** Flip one bit in `C[i-1]` and confirm that the same bit changes in `P[i]`. If the response rejects, check whether the rejection is a MAC failure or a parse failure — the first closes the branch, the second is a data-shape problem.
3. **Choose the branch.** IV branch if you can supply `IV`; sacrificial-block branch if block `i-1` is padding or a field the parser ignores; re-encryption branch if you can get the service to encrypt an attacker-chosen block in the right position.
4. **Define the baseline-vs-probe differential.** Baseline: original ciphertext, note the exact field value in the decrypted output. Probe: same ciphertext with the single bit flipped, note the field value and whether block `i-1` changed type. The differential is the field transition, not the raw bytes.
5. **Name the stop condition.** Stop at the first field transition that grants a different privilege, a different amount, or a different identity. A transition into unparseable bytes is not a finding.
6. **State the proof.** Report the block indices, the bit position, the plaintext field before and after, and the collateral effect on the preceding block. Record whether an authenticated envelope elsewhere would have caught the modification.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| IV accepted as a request parameter or cookie field | The first plaintext block is directly editable, so no sacrificial block is needed | Web session handlers, `AES/CBC` wrappers with `iv` in the payload |
| `role=user` and `role=admin` in a fixed-width serialised blob | Field offsets are stable and differ by a known bit, which is the whole attack precondition | Licence files, permission cookies, SAML-adjacent blobs |
| Same ciphertext with one flipped byte returns a 200 and a changed field | Unauthenticated CBC confirmed by behaviour, not by reading the provider string | Any decrypt endpoint that does not MAC |
| `pad(unpad(...))` applied before any integrity check | Integrity check happens after the malleable step, so the modification is never detected | Hand-rolled encrypt/decrypt helpers |
| Decrypt endpoint returns distinct parse errors for block 0 and block 1 corruption | Confirms block boundaries, which is what you need to aim the flip | Error-mapping review |
| `AES/GCM` with the record id in AAD | Modification is rejected regardless of block position, so the branch is closed | JCA, Go `cipher.AEAD`, `cryptography` AEAD |

## Worked Contrast

**Vulnerable: CBC session blob with the IV supplied by the client**

```python
# P[0] = D(C[0]) xor IV. Accepting "iv" from the client hands the attacker the
# first plaintext block with no collateral corruption at all.
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_session(payload: dict) -> dict:
    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["blob"])
    dec = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    return dict(kv.split("=", 1) for kv in pt.decode().strip("\x00").split(";"))
```

**Hardened: server-side IV, authenticated ciphertext, identity in AAD**

```python
# The IV never leaves the server, and the tag covers the whole envelope, so a
# single flipped bit is rejected before any field is parsed.
import base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_session(payload: dict, session_id: str) -> dict:
    blob = base64.b64decode(payload["blob"])
    nonce, body = blob[:12], blob[12:]
    aad = f"v1|sid={session_id}".encode()
    pt = AESGCM(SESSION_KEY).decrypt(nonce, body, aad)   # tag verified first
    return dict(kv.split("=", 1) for kv in pt.decode().split(";"))
```

**Why this matters:** The left function lets the caller choose the exact value that is XORed into the decrypted first block, so a bit edit becomes a plaintext edit with no noise to hide. The right function removes the caller's influence over the nonce and verifies a tag over the whole envelope, so the same bit edit fails authentication before the parser ever sees a byte.

## When It Is NOT This Issue

- **A CBC blob whose MAC is checked first.** If `verify(mac, iv||ct)` runs before `decrypt`, the flip is detected and the branch is unreachable. The finding would be about ordering, and the ordering is correct here.
- **A field change that only affects the attacker's own record.** Flipping your own role in your own session is a self-inflicted state change with no privilege boundary crossed; it belongs in a hardening note.
- **Corrupted block 0 that the parser rejects.** If every single-bit flip in the preceding block yields a parse error rather than a changed value, the format is protecting you accidentally. Record it as `Verified Safe` with the reason.
- **A fixed IV that is not client-controllable.** A static IV leaks equality of first blocks but gives the attacker no lever to aim a flip; that is a different, weaker finding.
- **Base64 that decodes to a length not divisible by 16.** The service is not doing CBC over your input at all, so measure the geometry again before assuming chaining.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `block-cipher-modes-and-padding-oracles-cbc-bit-flipping` based solely on surface keywords (`CBC flip`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `block-cipher-modes-and-padding-oracles-cbc-bit-flipping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: block-cipher-modes-and-padding-oracles-cbc-bit-flipping
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation`](../block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation/SKILL.md) - Cryptography Attacks (leaf)
- [`block-cipher-padding-oracle-exploitation`](../block-cipher-padding-oracle-exploitation/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `block-cipher-modes-and-padding-oracles-cbc-bit-flipping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/L5/ctf_search (1), CYBER_CPT/pentesterlab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
