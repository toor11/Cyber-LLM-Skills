---
name: classical-and-covert-encoding
description: "Decodes and breaks classical ciphers and encoding layers: Caesar, Vigenere, substitution, transposition, Morse, base variants, hex, and chained encodings. Use when facing CTF crypto, obfuscated payloads, or data that looks encoded rather than encrypted."
family: cryptography-attacks
tier: leaf
triggers: ["classical cipher", "caesar", "vigenere", "substitution cipher", "base64 decode", "encoding chain"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-463]
related: [symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension, password-hashing-and-kdf-attacks]
---

# Classical and Covert Encoding - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Classical and covert encoding covers two different jobs that share one skill because both are about recognising a transformation rather than breaking cryptography. The first job is decoding: identifying Caesar, Vigenere, substitution, base64, base32, hex, URL-safe variants, and Morse in an artefact, then recovering the plaintext from structure alone — index of coincidence for a monoalphabetic substitution, Kasiski or a Friedman estimate for a repeating-key Vigenere, and magic-byte and entropy checks for base64 that is really a compressed or encrypted blob. The second job is finding data hidden in a channel that is not supposed to carry data: appended bytes after a valid end-of-file marker, whitespace or zero-width characters inside text, metadata fields, and unused header bytes. Neither job is a cryptographic break, and the review question is almost always "does this channel cross a trust boundary" — an encoding that the application echoes back to a user can carry attacker-chosen content through a filter that only inspects decoded text, which turns an encoding question into an injection or data-exfiltration question. The precondition for the decoding branch is a sample you are authorised to read; for the covert-channel branch it is an artefact with a plausible carrier.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the artefact is printable and its alphabet is a subset of `A-Za-z0-9+/=` **THEN** try base64 variants first, then base32 and base58, and check the decoded bytes for a magic number before assuming text.
2. **IF** the decoded bytes are high-entropy with no magic number **THEN** stop treating it as encoding and treat it as ciphertext or compression; switch to [`crypto-implementation-review`](../crypto-implementation-review/SKILL.md).
3. **IF** the text is alphabetic with preserved word lengths **THEN** run a frequency and index-of-coincidence test before assuming a cipher; natural language shifts the index above the random baseline.
4. **IF** the artefact is a file with a valid end marker followed by extra bytes **THEN** the covert-channel branch applies: measure the appended region and check whether the parser ignores it.
5. **IF** the artefact is text with invisible characters **THEN** enumerate zero-width and tag codepoints before drawing conclusions; a single stray U+200B is a formatting bug, not a channel.
6. **IF** the encoded content is echoed back to another user **THEN** pivot to the injection question and treat the encoding as a filter-evasion detail, not the finding.
7. **IF** the carrier is an image or audio file **THEN** switch to [`steganography-and-covert-channels`](../steganography-and-covert-channels/SKILL.md); LSB analysis belongs there.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the carrier and the alphabet.** Record the file type from magic bytes rather than extension, then compute the character set of the payload region. The alphabet narrows the candidate transforms to a handful.
2. **Test decode, don't guess.** Run each candidate transform on the sample and score the output: printable ratio, magic-byte match, and compressed-size ratio. A transform that produces 95% printable ASCII is the right one; 40% means you guessed wrong.
3. **Choose the branch.** Encoding branch (recover plaintext and state what it reveals), hidden-channel branch (locate the carrier region and prove the parser ignores it), or filter-evasion branch (show that a decoder downstream sees attacker content).
4. **Define the baseline-vs-probe differential.** Baseline is the artefact as delivered. Probe is the same artefact with the suspect region removed or normalised. If behaviour is identical, the region is inert; if behaviour changes, the region is load-bearing and you can name what it carries.
5. **Name the stop condition.** Stop when one transform produces coherent output, or when normalising the carrier changes observable behaviour. Do not brute-force keys against a sample that decodes cleanly with a public transform.
6. **State the proof.** Report the transform, the offset or the region, the recovered content's nature (a flag, a credential, attacker-controlled text), and whether the channel crosses a trust boundary. If normalisation changes nothing, the disposition is `Verified Safe` and the artefact is decorative.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Trailing bytes after `FFD9` in a JPEG or after `IEND` in a PNG | An appended-data channel exists and the renderer ignores it | Image pipelines, upload validators that check only the header |
| Zero-width characters (U+200B, U+200C, U+FEFF) inside a comment or display name | A text carrier that survives most length and character filters | Web forms, chat messages, code-review comments |
| Base64 that decodes to `PK\x03\x04` or `\x1f\x8b` | The "encoding" is really an archive or gzip, so the review target is the extraction path | File upload handlers, attachment processors |
| Index of coincidence near 0.066 in a 200+ character sample | Monoalphabetic substitution, not a modern cipher | CTF artefacts, obfuscated configuration |
| Repeated key-length spikes at 8, 16, 24 in a Kasiski pass | Repeating-key Vigenere with a short key | Historical cipher samples, puzzle data |
| An upload validator that inspects `Content-Type` but not pixel dimensions | The validator checks the declared type, so a polyglot or appended payload passes | WAF rules, image proxies |

## Worked Contrast

**Vulnerable: trailing data accepted and later served back**

```python
# The handler validates the magic bytes and then stores the whole blob, including
# everything after the image's end marker, and serves it from the same origin.
def store_upload(raw: bytes, name: str) -> str:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a png")
    path = os.path.join(UPLOAD_DIR, secure_name(name))
    open(path, "wb").write(raw)      # trailing region preserved verbatim
    return f"/media/{os.path.basename(path)}"
```

**Hardened: re-encode to a canonical form and drop the carrier region**

```python
# Decode, re-encode, and store only the pixels. The output has no room for
# attacker-appended bytes and no metadata to carry a channel.
from io import BytesIO
from PIL import Image

def store_upload(raw: bytes, name: str) -> str:
    with Image.open(BytesIO(raw)) as img:
        img.verify()                                  # structural check
    with Image.open(BytesIO(raw)) as img:
        clean = BytesIO()
        img.convert("RGB").save(clean, format="PNG")   # canonical re-encode
    path = os.path.join(UPLOAD_DIR, secure_name(name))
    open(path, "wb").write(clean.getvalue())
    return f"/media/{os.path.basename(path)}"
```

**Why this matters:** The left function proves only that the first eight bytes look like a PNG, so the region after `IEND` survives untouched and can carry any payload the uploader wants, served later from the application's own origin. The right function re-derives the artefact from decoded pixels, which discards appended bytes and metadata by construction rather than by matching a blocklist.

## When It Is NOT This Issue

- **Base64 in a URL or a JWT segment.** That is the transport encoding the protocol requires; it is not obfuscation and not a finding.
- **Trailing bytes in a format that defines them.** ZIP allows a comment after the central directory, and MP4 boxes can be extended. Check the format spec before calling appended data a channel.
- **A single zero-width character from a copy-paste.** One stray U+FEFF at the start of a file is a byte-order mark, not a covert channel.
- **High index of coincidence in non-English text.** Language matters: the baseline for a given alphabet and language differs, so compare against the right reference rather than 0.066 by default.
- **An encoded blob that decodes to nothing recognisable.** Without a magic byte, a plausible structure, or a key, "this may be encoded" is a hypothesis, not a finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `classical-and-covert-encoding` based solely on surface keywords (`caesar shift`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `classical-and-covert-encoding` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: classical-and-covert-encoding
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
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md) - Cryptography Attacks (core)
- [`rsa-attacks`](../rsa-attacks/SKILL.md) - Cryptography Attacks (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `classical-and-covert-encoding` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/github_security_md (4), CYBER_CPT/awesome_list (3), CYBER_CPT/ctftime (2), cyber-security/security-code (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
