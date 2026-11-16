---
name: steganography-and-covert-channels
description: "Detects and extracts hidden data: LSB steganography, appended data, metadata hiding, and covert channels in protocols and files. Use in forensics, CTF, or when data may be smuggled past inspection."
family: cryptography-attacks
tier: leaf
triggers: ["steganography", "lsb steganography", "hidden data", "covert channel", "steghide"]
cwe: [CWE-514]
owasp: []
attack: []
capec: [CAPEC-590]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Steganography and Covert Channels - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Steganography review has two directions and they are often confused. The detection direction asks whether an artefact carries hidden data: LSB substitution raises the noise floor in the least-significant plane and shows as a characteristic histogram pair-of-values pattern; appending data after a container's end marker leaves bytes the renderer never reads; palette and metadata fields — PNG `tEXt`, JPEG EXIF comments, ID3 tags, PDF incremental updates — can carry arbitrary payloads that survive most validators. The emission direction asks whether a system provides a channel to hide data: a field that is stored and echoed but never validated, whitespace in a comment, zero-width characters in a display name, or an unused protocol field. The measure in both directions is capacity and detectability, and the review question is trust-boundary shaped: a covert channel matters when it crosses a boundary that a filter is supposed to enforce, which turns "hidden data" into "data exfiltration" or "filter bypass". The precondition for a finding is a carrier that survives the pipeline and a boundary the carrier crosses.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the artefact is an image and the question is hidden data **THEN** start with the least-significant-bit plane and the container's end marker; those two checks cover most cases.
2. **IF** the artefact is a document or an archive **THEN** check metadata and trailing bytes before any pixel analysis; they are cheaper and more common.
3. **IF** the suspicious carrier is a text field **THEN** enumerate format and control codepoints before drawing conclusions; a single mark is not a channel.
4. **IF** the channel crosses a filter that inspects decoded content **THEN** the finding is filter bypass, not steganography; state what the filter reads and what it misses.
5. **IF** the carrier capacity is a few bytes and the pipeline re-encodes the artefact **THEN** the channel does not survive; measure the capacity after the pipeline.
6. **IF** the target is a covert network channel **THEN** switch to the DNS and tunnelling skills in the detection family; this skill is about carrier artefacts.
7. **IF** the artefact is audio or video **THEN** the same principles apply but the tooling differs; record which container and which layer you examined.
8. **IF** the carrier is an image whose pixels a downstream renderer consumes **THEN** pair this review with [`firmware-extraction-and-emulation`](../../mobile-hardware-wireless-ics/firmware-extraction-and-emulation/SKILL.md) when the image is a device artefact, or with [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) when the payload is an encoding rather than a channel.
9. **IF** you need the blue-team disposition for a channel that crossed a boundary **THEN** pivot to [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the carrier and the layer.** Container (file, text field, protocol field), the layer that survives the pipeline (pixels, metadata, trailing bytes, codepoints), and the capacity at that layer.
2. **Measure the baseline.** For an image, the LSB plane of the unmodified artefact; for text, the codepoint census. The baseline tells you what "normal" is for this carrier before you look for anomalies.
3. **Choose the branch.** LSB anomaly, appended region, metadata payload, or text codepoint channel. Each has a specific detector and a specific capacity.
4. **Define the baseline-vs-probe differential.** Baseline: the artefact as delivered. Probe: the same artefact re-encoded through the pipeline's canonicaliser. If the payload survives, the channel is real; if the canonicaliser strips it, the control is the re-encode.
5. **Name the stop condition.** Stop when one layer shows a payload, or when every layer is clean at a stated capacity. Do not attempt to extract a payload you cannot attribute.
6. **State the proof.** Report the layer, the capacity in bytes, the surviving check, and the boundary crossed. If the pipeline re-encodes everything, record `Verified Safe` with the canonicalisation step named.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Equal counts of adjacent pixel values in the LSB plane | LSB substitution, which pushes pairs of values toward equal frequency | PNG and BMP pipelines that pass pixels through |
| Bytes after `IEND` or `FFD9` with non-zero length | Appended-region channel that the renderer ignores and the pipeline preserves | Upload handlers, CDN originals |
| A `tEXt` or `EXIF UserComment` field with high entropy | Metadata payload, which survives re-encode in most libraries by default | Image processing services |
| Runs of U+200B or U+FEFF in a submitted comment | Text codepoint channel that survives length and character filters | Web forms, chat, code review comments |
| A pipeline that decodes and re-encodes pixels | The canonicalisation that removes LSB and appended data by construction | `PIL`/ImageMagick re-encode steps |
| An upload validator that checks magic bytes only | The validator reads the header, so anything after it passes | WAF and application upload checks |

## Worked Contrast

**Vulnerable: upload stored verbatim, so both the appended region and the LSB payload survive**

```python
# The only check is the declared content type, and the bytes are stored untouched,
# so appended data and LSB payloads reach every consumer of the object.
def accept_upload(file, name: str) -> str:
    if file.content_type not in ("image/png", "image/jpeg"):
        raise ValueError("unsupported")
    path = os.path.join(MEDIA, secure_name(name))
    with open(path, "wb") as fh:
        fh.write(file.read())          # verbatim, including trailing region
    return f"/media/{os.path.basename(path)}"
```

**Hardened: decode, canonicalise, re-encode, and store only the derived pixels**

```python
# Pixels are decoded and re-encoded, which drops the appended region, the LSB
# payload that did not survive resampling, and most metadata by default.
from io import BytesIO
from PIL import Image

def accept_upload(file, name: str) -> str:
    raw = file.read()
    with Image.open(BytesIO(raw)) as img:
        img.verify()
    with Image.open(BytesIO(raw)) as img:
        clean = img.convert("RGB")
        if max(clean.size) > 4096:
            raise ValueError("too large")
        buf = BytesIO()
        clean.save(buf, format="PNG", optimize=True)   # no metadata carried over
    path = os.path.join(MEDIA, secure_name(name))
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return f"/media/{os.path.basename(path)}"
```

**Why this matters:** The left handler stores whatever bytes arrived, so a payload appended after the end marker or encoded in the least-significant bits reaches every downstream consumer unchanged. The right handler rebuilds the artefact from decoded pixels, which discards the appended region and metadata and disrupts pixel-level payloads.

## When It Is NOT This Issue

- **Metadata that the format defines, such as a camera's EXIF block.** Defined fields are not a channel unless they carry attacker-chosen content across a boundary.
- **A single zero-width character in pasted text.** Formatting noise, not a channel; alert on runs.
- **Bytes after a container marker in a format that allows them, such as a ZIP comment.** Check the spec before calling it appended data.
- **LSB differences introduced by lossy compression.** JPEG quantisation changes low bits naturally, so an LSB anomaly argument needs a lossless format.
- **A carrier that the pipeline re-encodes.** If the canonicaliser runs, the capacity is zero and the channel is closed by construction.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `steganography-and-covert-channels` based solely on surface keywords (`LSB`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `steganography-and-covert-channels` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: steganography-and-covert-channels
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-514`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `steganography-and-covert-channels` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-514`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctf_search (8), cyber-security/CyberSec-Dataset (2), CYBER_CPT/atomic_red_team (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
