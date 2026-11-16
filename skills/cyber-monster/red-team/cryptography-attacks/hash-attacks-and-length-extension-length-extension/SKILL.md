---
name: hash-attacks-and-length-extension-length-extension
description: Hash length extension attacks. Covers extending Merkle-Damgard hashes when used as naive MACs, including padding reconstruction and forged messages. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["length extension attack", "hash append", "merkle damgard"]
cwe: [CWE-328]
owasp: []
attack: []
capec: [CAPEC-463]
related: [hash-attacks-and-length-extension, hash-attacks-and-length-extension-collision-and-bypass, classical-and-covert-encoding, symmetric-cipher-attacks]
parent: hash-attacks-and-length-extension
---

# Hash Attacks and Length Extension Length Extension - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Length extension is the concrete arithmetic behind the parent class. A Merkle-Damgard hash keeps an internal state of `n` bits — 256 for SHA-256, split into eight 32-bit words — initialises it with fixed constants, and absorbs the message in 64-byte blocks. When the message ends, the padding is appended deterministically: a `0x80` byte, then zeros, then the message length in bits as a 64-bit big-endian integer, and the state after that final block *is* the digest. The consequence: given `H(m)` and `len(m)`, an attacker sets the internal state to `H(m)`, appends their own block, and produces a valid digest for `m || glue || suffix` where `glue` is the exact padding of `m`. Nothing secret is needed. The only unknowns are the length of the secret in `H(secret || msg)` and whether the verifier parses the extended message in a way that helps the attacker — which is why the finding needs both the extension and a parser that tolerates trailing bytes. `hashpump` automates the arithmetic. The defence is HMAC, which hashes `(K xor opad) || H((K xor ipad) || msg)` and is provably not extendable, or a length-prefixed frame that makes the trailing region unambiguous.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the verifier compares `hash(secret || msg)` to a supplied value **THEN** this is the skill; the parent [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) carries the wider decision table.
2. **IF** you can infer or brute-force `len(secret)` **THEN** the arithmetic is fully determined; `hashpump -k` takes the length directly.
3. **IF** the verifier rejects messages containing bytes above `0x7f` **THEN** the glue padding may be filtered, which changes the feasibility but not the construction defect.
4. **IF** the verifier parses only up to a delimiter that the glue padding cannot contain **THEN** record the mitigation and downgrade to a hardening note.
5. **IF** the hash is SHA-3, BLAKE2, or BLAKE3 **THEN** the sponge or tree construction is not extendable this way; the disposition is a control.
6. **IF** the hash is MD5 or SHA-1 **THEN** both the extension and the collision branches exist; keep them as separate findings.
7. **IF** the target is a signed cookie or a webhook signature **THEN** the consequence is field injection, which is what makes the extension worth reporting.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the construction from code.** You need the literal hash over a concatenation, in a verifier, with the digest compared to attacker-supplied input. A signer with no verifier is not reachable.
2. **Determine the secret length.** Try lengths from the format (16, 24, 32 bytes are common), or brute-force the glue length against the verifier's acceptance as the oracle. Record the length you settled on.
3. **Compute the extension offline.** `hashpump -s <digest> -d <known message> -a <suffix> -k <secret_len>` returns the new message and the new digest. Both are the probe; neither contains the secret.
4. **Define the baseline-vs-probe differential.** Baseline: `(msg, digest)` verifies and produces the original fields. Probe: `(msg || glue || suffix, digest')` either verifies with the extra field present, or fails. The differential is the extra field appearing in the parsed output.
5. **Name the stop condition.** Stop at the first accepted extended message in an offline reproduction. Do not send forged values to a production endpoint, and do not attempt to recover the secret.
6. **State the proof.** Report the hash, the assumed secret length, the appended suffix, the verifier's acceptance, and the injected field. If the verifier rejects the probe for a structural reason, name that reason as the compensating control.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `hashlib.sha256(SECRET + msg)` in the verify branch | Secret-prefix construction, so extension is possible with the secret length alone | Python and Node request signing |
| A verifier that splits the message on `&` after checking the digest | Trailing bytes become new fields, which is what makes the extension an escalation rather than a curiosity | Query-string tokens, form-encoded claims |
| `hashpump` succeeds at `-k 24` and `-k 32` but not `-k 16` | The secret length, established by differential rather than by guessing once | Offline reproduction |
| `hashlib.blake2b` or `sha3_256` in the same position | Non-extendable construction, so the branch is closed even with concatenation | Modern libraries |
| Digest compared with `==` after the extension check | A second, independent defect; route it to the constant-time skill | Any verifier |
| A verifier that requires the message to end at a known delimiter | The glue padding normally cannot satisfy the delimiter, which is the accidental control | Strict parsers |

## Worked Contrast

**Vulnerable: secret-prefix hash over a message the parser will extend**

```python
# H(secret || msg) is extendable. Because the verifier splits on "&", the attacker's
# appended suffix becomes a field they were never granted.
import hashlib

def verify(msg: bytes, mac: str) -> dict:
    if hashlib.sha256(SECRET + msg).hexdigest() != mac:
        raise ValueError("bad mac")
    return dict(p.split("=", 1) for p in msg.decode().split("&"))
```

**Hardened: HMAC plus a declared frame length the padding cannot forge**

```python
# HMAC is not extendable, and the frame carries its own length so any trailing
# bytes are rejected before the field split happens.
import hashlib, hmac

def verify(msg: bytes, mac: str) -> dict:
    if not hmac.compare_digest(mac, hmac.new(SECRET, msg, hashlib.sha256).hexdigest()):
        raise ValueError("bad mac")
    head, _, body = msg.partition(b"|")
    if int(head) != len(body):
        raise ValueError("bad frame")
    return dict(p.split(b"=", 1) for p in body.split(b"&"))
```

**Why this matters:** The left verifier authenticates any message the attacker can derive from a known digest, so the appended `&role=admin` arrives with a valid MAC and the parser happily grants it. The right verifier's construction cannot be extended from a known digest, and the length prefix means even a correctly-framed message cannot have bytes added without failing the frame check.

## When It Is NOT This Issue

- **SHA-3, BLAKE2, or BLAKE3 with a concatenation.** Sponge and tree constructions do not expose the internal state as a digest, so the arithmetic does not apply. Report it as a construction smell only.
- **A verifier that requires a fixed message length.** If the code rejects any message whose length differs from the expected one, the extended message cannot be submitted.
- **Extension on a message whose parsed fields do not matter.** If the verifier only checks a boolean and discards the message, the extra field grants nothing.
- **A digest used as a cache key over trusted content.** No attacker-supplied digest and no verifier means no finding.
- **`hash(secret || msg)` on a path that is never reachable with attacker input.** Dead code or an admin-only tool; note it as cleanup.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `hash-attacks-and-length-extension-length-extension` based solely on surface keywords (`hashpump`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hash-attacks-and-length-extension-length-extension` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: hash-attacks-and-length-extension-length-extension
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-328`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension-collision-and-bypass`](../hash-attacks-and-length-extension-collision-and-bypass/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hash-attacks-and-length-extension-length-extension` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-328`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/pentesterlab (2), CYBER_CPT/skullsecurity (1), CYBER_CPT/secwiki (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
