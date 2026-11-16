---
name: crypto-implementation-review
description: "Reviews cryptographic code for real-world mistakes: home-made constructions, key management errors, unsafe defaults and misuse of library APIs. Use when auditing an implementation rather than breaking a primitive."
family: cryptography-attacks
tier: core
triggers: ["crypto code review", "implementation mistake", "key management", "crypto misuse"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Crypto Implementation Review - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Implementation review is the skill that catches the defect nobody classified: home-made constructions, a mode chosen by a default rather than a decision, a key that lives in source, an IV derived from a counter that resets on restart, a KDF applied once where a KDF with a work factor was needed, or a protocol that concatenates fields without length prefixes so two different messages serialise identically. The unifying question is not "is this primitive broken" but "does the composition preserve the property the protocol needs" — confidentiality under chosen plaintext, integrity under chosen ciphertext, and agreement on message boundaries under adversarial encoding. Canonicalisation failures deserve their own line because they are the most common real defect: if `encrypt(a) || encrypt(b)` equals `encrypt(a || b)` for some pair, the construction has an ambiguity that a MAC over the concatenation cannot detect. The review output is a finding only when a specific composition violates a specific property under a specific attacker capability; everything else is a note, and separating those two lists is most of the job.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the code implements a primitive rather than calling a library **THEN** start with the composition question: what property does it claim, and what happens under chosen-input ambiguity.
2. **IF** the defect is a specific mode or padding misuse **THEN** route to [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) or [`aead-aes-gcm-and-chacha20-misuse`](../aead-aes-gcm-and-chacha20-misuse/SKILL.md); this skill is for defects that span primitives.
3. **IF** the defect is a key that lives in source, a config file, or an environment variable without rotation **THEN** route to [`envelope-encryption-and-kms-tenant-isolation`](../envelope-encryption-and-kms-tenant-isolation/SKILL.md) and record the custody gap here.
4. **IF** the defect is a comparison or an index on secret data **THEN** switch to [`constant-time-and-crypto-side-channel-code-audit`](../constant-time-and-crypto-side-channel-code-audit/SKILL.md).
5. **IF** the defect is randomness **THEN** switch to [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md).
6. **IF** the code calls a vetted library with sane parameters and the protocol framing is length-prefixed **THEN** the disposition is `Verified Safe`; say which library and which parameters you checked.
7. **IF** the construction is a hash-based MAC built by hand (`md5(secret || msg)`) **THEN** switch to [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md); that is a specific break, not a review note.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Write down the claim.** For each construction, state the property it is supposed to provide — confidentiality, integrity, authenticity, agreement — and the attacker capability assumed. A construction with no written claim cannot be reviewed, only criticised.
2. **Map the composition.** List the primitives, the order they are applied, and every field boundary. Boundary ambiguity is where implementation bugs actually live: concatenation without a length prefix, JSON with duplicate keys, a delimiter that can appear in a field.
3. **Probe the ambiguity.** Construct two distinct logical messages that serialise to the same bytes and check whether the verifier accepts both. That is the differential: baseline is one message, probe is the pair that collides in the encoding but not in the intent.
4. **Check the parameter set against the threat.** Key size against data lifetime, KDF work factor against hardware, IV derivation against restart behaviour, and rotation against the deployment's actual message volume.
5. **Name the stop condition.** Stop when you have either a demonstrated ambiguity, a parameter below the claimed security level, or a key-custody gap. Do not enumerate every style issue in the file.
6. **State the proof.** Report the property, the composition step that breaks it, the two colliding messages or the parameter value, and the minimal composition that restores it. Everything else goes in a separate note list with no severity.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `md5(secret + msg)` or `sha1(key + data)` as a MAC | Length-extension break, so the "MAC" is forgeable without the key | Hand-rolled session and webhook signing |
| `encrypt(a) + encrypt(b)` verified as one blob | Boundary ambiguity: the concatenation is also a valid encryption of a different message | Custom token formats, envelope helpers |
| `AES.new(key, AES.MODE_CBC)` with no `iv=` and no MAC | Library default chosen instead of decided, which is how fixed-IV CBC ships | PyCryptodome call sites |
| `hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)` | Work factor far below current guidance for a password store | Legacy auth code, migration paths |
| Key literal in source or a checked-in `.env` | Custody gap, so rotation and blast radius are both unbounded | Repos with committed config, container images |
| `json.loads` on a signed payload with duplicate keys | Parser differential: verifier and consumer may read different values from one signed blob | JWT-adjacent custom formats, webhook handlers |

## Worked Contrast

**Vulnerable: hand-rolled token with ambiguous framing and a concatenation MAC**

```python
# Two defects in six lines: sha256(key + msg) is length-extendable, and the "|"
# delimiter can appear inside user_id, so two different claims produce one token.
import hashlib

def issue(user_id: str, role: str) -> str:
    body = f"{user_id}|{role}"
    mac = hashlib.sha256(KEY + body.encode()).hexdigest()
    return f"{body}|{mac}"

def check(token: str) -> dict:
    user_id, role, mac = token.rsplit("|", 2)
    body = f"{user_id}|{role}"
    return {"user_id": user_id, "role": role,
            "ok": hashlib.sha256(KEY + body.encode()).hexdigest() == mac}
```

**Hardened: HMAC over an unambiguous encoding, verified before parsing**

```python
# HMAC-SHA256 is not length-extendable, the body is length-prefixed so the field
# boundary cannot be moved, and the tag is checked before any interpretation.
import hmac, hashlib, json

def issue(sub: str, role: str) -> str:
    body = json.dumps({"sub": sub, "role": role}, separators=(",", ":"), sort_keys=True).encode()
    tag = hmac.new(KEY, body, hashlib.sha256).hexdigest()
    return f"{len(body)}.{body.decode()}.{tag}"

def check(token: str) -> dict:
    n, body, tag = token.split(".", 2)
    if int(n) != len(body):                       # length prefix is enforced
        raise ValueError("bad frame")
    expected = hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected):    # verify before parsing
        raise ValueError("bad tag")
    return json.loads(body)
```

**Why this matters:** The left token is forgeable by length extension and its delimiter lets a crafted `user_id` shift the field boundary so a low-privilege token parses as a high-privilege one. The right token uses a MAC that resists extension, makes the frame self-describing with a length prefix, and verifies before it trusts any parsed value.

## When It Is NOT This Issue

- **A library call with an explicit mode, a per-message random IV, and a MAC.** That is a correct composition; review it once and record the parameters you verified rather than re-litigating it.
- **A custom format that is only ever consumed by the same process with no adversary in the middle.** Ambiguity without an attacker is a maintainability note. Say which boundary is missing.
- **Base64 or hex in a token.** Encoding is not framing. A delimiter inside base64 output cannot appear, so the ambiguity argument does not apply.
- **A short key in a test fixture or a sample config.** Test keys are not deployed secrets; confirm the fixture path is not loaded in production before filing.
- **A KDF work factor that looks low but is rate-limited at the service layer.** The work factor is one control among several; state the composition rather than the number alone.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `crypto-implementation-review` based solely on surface keywords (`home-made crypto`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `crypto-implementation-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: crypto-implementation-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `crypto-implementation-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 40 |
| Distinct dataset sources | 7 |
| Top sources | securecode-web (20), OffsecCyber (7), SecEval/apple_platform_security (4), cyber-security/CyberSec-Dataset (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
