---
name: file-carving-and-recovery
description: "Recovers deleted and fragmented files: carving signatures, container parsing and handling compressed or encrypted remnants. Use when files were deleted but may still be recoverable."
family: digital-forensics
tier: leaf
triggers: ["file carving", "deleted file recovery", "data carving"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# File Carving and Recovery - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Carving is pattern matching over bytes with no filesystem help, and its accuracy is bounded by fragmentation, not by the quality of the signature list. A carver finds a header, optionally looks for a footer, and emits the bytes between them; if the file was stored contiguously in a fresh image that works almost perfectly, and if it was fragmented the output is the first fragment followed by whatever happened to be allocated next — a JPEG that decodes correctly at the top and turns to noise partway down, or a ZIP whose central directory does not match its entries. Metadata recovery is strictly better where it is available: on NTFS a deleted record keeps its `$STANDARD_INFORMATION`, `$FILE_NAME` and `$DATA` attributes until the record is reused, so a resident file is recoverable from the MFT record alone with no carving at all, and a non-resident file is recoverable while its clusters remain unallocated. FAT loses the cluster chain but keeps the name, size and start cluster, so recovery succeeds when the allocation was contiguous. ext4 usually zeroes the extent entries and the size, so carving is the only option even though the name may survive in the directory block. Every carved output therefore needs validation before it is called a recovery: decode the structure (JPEG markers and scan continuity, ZIP central directory, PDF cross-reference table, PNG chunk CRCs), compare dimensions and metadata against the format's own header, and where possible match a known hash. Container and archive formats make this harder because their headers can be encrypted (a password-protected 7z looks like an opaque header) or compressed (a DEFLATE stream must be decoded before structure is visible), and a partially carved container is worse than useless in a report because it looks complete to a human and fails to a parser.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the filesystem is NTFS **THEN** try metadata recovery first — parse `$MFT`, find records with the in-use flag cleared, and extract resident data directly; **IF** that yields nothing **THEN** carve, because the record was reused and only pattern matching remains.
2. **IF** the filesystem is ext4 or another journaling filesystem that zeroes extents **THEN** go straight to carving on a copy, and treat the surviving directory name as context rather than as a path.
3. **IF** the target is one known file type **THEN** configure the signature set narrowly and carve only that type, because a broad signature list multiplies false positives and costs you the ability to explain precision; **IF** the target is unknown **THEN** run a feature extractor over the image first and carve the types it actually reports.
4. **IF** any carved result must be reported **THEN** validate it structurally and record the validation result beside the hash; **IF** it fails validation **THEN** report it as a fragment with its byte range, never as a recovered file.
5. **IF** the file was written to a filesystem with a journal or change log **THEN** check those for the original path and allocation before carving, because a carver cannot recover a name and the journal may.
6. **IF** the remnant is inside a compressed or encrypted container **THEN** state the container's protection in the output; carving cannot see through encryption, and a "no results" from an encrypted container is not evidence of absence.
7. **IF** telemetry source covering `carving` / `signature` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need carving commands and validation checks | [`QUERIES.md`](QUERIES.md) | One class per recovery route |
| Need carver flags and feature-extractor usage | [`TOOLS.md`](TOOLS.md) | `photorec`, `foremost`, `scalpel`, `bulk_extractor` |
| Need the filesystem structures underneath | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | MFT, inode and `$Bitmap` ownership |
| Need to recover a deleted download target | [`browser-and-application-forensics`](../browser-and-application-forensics/SKILL.md) | The URL and timestamp come from the profile |
| Need to handle a carved sample safely | [`sample-handling-and-safety`](../../malware-analysis/sample-handling-and-safety/SKILL.md) | Malware handling rules |
| Need the carved content in a timeline | [`log-and-timeline-analysis`](../log-and-timeline-analysis/SKILL.md) | Placing fragments without timestamps |
| Need scripted carving pipelines | [`static-pe-elf-apk-feature-extractor-scripting`](../../security-automation-and-tool-development/static-pe-elf-apk-feature-extractor-scripting/SKILL.md) | Automation ownership |
| Need case shapes for wiped or partially overwritten media | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Carve only from a verified image copy, never from the master and never from a mounted device. Record the image hash, the exact byte range or partition offset carved, and the carver version — a carver's output is not reproducible across versions without that record.
2. **Choose the branch from the filesystem and the remnant.** Metadata recovery where the filesystem kept records; journal or change-log lookup where the filesystem kept a log; carving where neither survives. Write the branch and the reason for it into the output, because "we carved" without saying why metadata failed reads as an incomplete investigation.
3. **Establish a baseline-versus-probe differential.** Baseline is a carve of the same image type with the same signature set in a region you know to be free of relevant files — the false-positive rate of that carver on that image. Probe is the incident region. Report the rate, because a carver that emits forty thousand JPEGs from a browser cache has not found forty thousand pieces of evidence.
4. **Name the stop condition.** Declare `Inconclusive` when the target region has been overwritten (allocation shows another file and the signature search returns nothing), when fragmentation is heavy enough that validation fails on every candidate, when the container is encrypted, or when the only candidates come from a region whose original owner cannot be determined.
5. **State what counts as proof.** Proof is a carved artifact that passes structural validation plus one independent agreement: a matching reference hash, a matching size and dimension in a corroborating record, or a journal entry naming the path with an allocation that overlaps the carved byte range. A valid file with no corroboration proves bytes existed, not which file they were.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| JPEG that decodes with no error and whose EXIF dimensions match its frame header | Carved image file from unallocated space | A structurally complete image existed in that byte range; if fragmented, only the first fragment is present |
| JPEG that decodes for N blocks then shows a discontinuity | Carved image fragment | The join point is the fragmentation boundary; report the byte range, not a whole file |
| ZIP whose central directory lists the entries actually present | Carved archive or OOXML document | The archive was stored contiguously and is complete enough to enumerate; a mismatched directory means truncation |
| MFT record with the in-use flag cleared and resident `$DATA` intact | NTFS metadata recovery | The exact file content, with its original name and both timestamp sets, recovered with no carving |
| FAT directory entry with `0xE5` first byte, intact size and start cluster, chain zeroed | FAT metadata recovery | A contiguous recovery is possible from the recorded start cluster and size |
| High-entropy region at a container header offset with no readable structure | Encrypted container | Encryption was applied to the container; carving cannot proceed past the header |
| Carve output count orders of magnitude above the expected file population | Carver false-positive population | The signature set is too broad for that image; precision must be measured before any candidate is cited |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`carving`):**

```text
# Runs every signature against the whole image and counts the output.
photorec /log /d /cases/out /cases/16/disk.dd
ls /cases/out/recup_dir.1 | wc -l
# No target type, no baseline region, no validation of any output, and the
# count is presented as if it were a number of recovered evidence files.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
IMG=/cases/16/disk.dd
OUT=/cases/16/carve

mkdir -p "$OUT"
# 1. Narrow signature set for the one type under investigation.
printf 'jpg y 20000000 \\xff\\xd8\\xff\\xe0 \\xff\\xd9\n' > "$OUT/jpeg.conf"

# 2. Carve only the region of interest, from the image, never a mount.
foremost -c "$OUT/jpeg.conf" -t jpg -i "$IMG" -o "$OUT" -q

# 3. Baseline the same carver on a known-benign region for a false-positive rate.
foremost -c "$OUT/jpeg.conf" -t jpg -i "$IMG" -o "$OUT/baseline" \
  -T -q 2>/dev/null || true

# 4. Validate every candidate structurally, and keep only what decodes cleanly.
python3 - <<'PY'
import pathlib
from PIL import Image
good = bad = 0
for p in pathlib.Path("/cases/16/carve/jpg").rglob("*"):
    if not p.is_file():
        continue
    try:
        with Image.open(p) as im:
            im.verify()
        good += 1
    except Exception:
        bad += 1
print(f"validated={good} rejected={bad}")
PY
```

**Why this matters:** the strong form scopes the signature set to the type under investigation, measures the carver's baseline noise, and validates every candidate before counting it — so the reported number is a number of structurally sound images rather than a number of byte patterns.

## When It Is NOT This Issue

- **Ordinary cache and thumbnail populations:** browser caches, thumbnails and application temp directories hold thousands of small images and documents by design. A carve that finds them has found normal application behaviour, not evidence.
- **Filesystem compression and sparse files:** a compressed or sparse file's allocated bytes differ from its logical size, and a naive read yields zeros or repeated patterns that look like an overwritten region. Check allocation against size before calling a region empty.
- **Overwritten-but-allocated clusters:** a cluster allocated to another file after the deletion contains the new file's bytes. Signature hits inside an allocated cluster belong to the current owner, and must not be attributed to the deleted file.
- **Partial downloads and truncated writes:** an application that crashed mid-write leaves a structurally invalid file that a carver may emit as a candidate. A file that never existed in complete form is not a recovered file.
- **Backup and deduplication artifacts:** content-addressed stores and snapshots contain copies of files that were legitimately deleted from the live volume. Their presence proves a backup exists, not that someone tried to destroy evidence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `carving` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the image hash, carved byte range and carver version are recorded, and the carve ran against a copy rather than a mount.
- [ ] **Branch justified:** the output states why metadata recovery was unavailable or insufficient before carving was used.
- [ ] **Differential defined:** the carver's baseline noise on that image was measured, and the reported candidates are a validated subset rather than a raw count.
- [ ] **Stop condition cleared or declared:** overwrite, fragmentation, encryption and unattributable regions were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: file-carving-and-recovery
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `file-carving-and-recovery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 6 |
| Top sources | Forensic_Toolkit_Dataset (5), CYBER_CPT/ctf_search (3), bugbounty-hunter-v1 (2), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 5 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
