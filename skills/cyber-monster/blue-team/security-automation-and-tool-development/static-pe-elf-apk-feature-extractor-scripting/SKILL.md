---
name: static-pe-elf-apk-feature-extractor-scripting
description: "Develops non-executing static binary and Android APK feature extractors (`pefile`, `lief`, `androguard`/`apkutils`, `capa` rules): computing import hashes (`imphash`), section Shannon entropy, authenticode metadata, and LAMDA-style Android permission/intent/suspicious-API vectors inside size/zip-bomb guards. Use when building malware triage or ML feature pipelines."
family: security-automation-and-tool-development
tier: core
triggers: ["pefile feature extractor", "apk static feature script", "imphash python", "capa rule runner", "lamda features"]
cwe: [CWE-506]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
---

# Static PE ELF APK Feature Extractor Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)

## Mechanism and Preconditions

Static feature extraction converts a binary into numbers and strings without running it, and the value of every feature depends on which parser produced it. For PE files, `pefile` exposes the import directory (`get_imphash()` hashes the ordered `library.function` list, which is why it clusters malware families and also why it collides across benign applications built from the same framework), section headers with raw data for entropy, resources, and signature data for authenticode metadata. `lief` covers PE/ELF/Mach-O with one API and is the better choice for cross-format pipelines. For Android, `androguard`'s `AnalyzeAPK` returns the `APK`, its DEX list, and an `Analysis` object with cross-references — enough for LAMDA-style vectors (permissions, intents, API calls, suspicious strings) that feed a classifier. `capa` sits above the parsers: it matches capability rules against disassembled features and reports behaviours rather than bytes. The engineering constraints are the same across formats. Everything is bounded — a section claiming a 4 GB raw size, an APK with a decompression bomb, or a nested archive must be refused before allocation. Everything is deterministic — the same bytes must produce the same feature vector, or a model trained on it is unreproducible. And nothing executes: no `subprocess` on the sample, no dynamic import, no emulator startup in the static path.

- **CWE-506 (Embedded Malicious Code):** the sample is code by definition; extraction reads metadata and bytes without granting it a process.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sample is a PE **THEN** use `pefile.PE(path, fast_load=True)` plus `parse_data_directories([...])` for the directories you need, compute `get_imphash()`, and skip sections whose `SizeOfRawData` exceeds the cap.
2. **IF** you need one API across PE/ELF/Mach-O **THEN** use `lief.parse(path)` and read `imported_functions`/`sections` from the format-specific object rather than maintaining three parsers.
3. **IF** the sample is an APK **THEN** use `androguard.misc.AnalyzeAPK(path)` and read permissions, intents, and API calls from the returned objects; enforce an uncompressed-size cap first.
4. **IF** you need behaviour-level labels rather than raw features **THEN** run `capa` (`capa -r <rules> -s <sigs> sample.exe`) or the `flare-capa` library, and keep its output as a separate signal from the numeric vector.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `static-pe-elf-apk-feature-extractor-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable extractor shapes | [`QUERIES.md`](QUERIES.md) | PE/APK skeletons, entropy maths, cap checks, capa invocation |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `pefile`, `lief`, `androguard`, `capa` entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Parser-crash and non-determinism incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Sample-handling handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `pefile` (PE import hash, sections, authenticode) for Windows samples, `lief` for cross-format parsing, `androguard` (`AnalyzeAPK`) for Android, and `flare-capa` for capability labels — all static, all bounded
- **Mandatory Self-Validation Command:** `python -m py_compile feature_extract.py`

1. **Confirm the inputs.** Establish the sample formats in scope, the size and uncompressed-size caps, the feature schema the downstream consumer expects (numeric vector, named dict, or both), and whether capability labels are needed. Confirm the sample is stored in a non-executable location with recorded hashes.
2. **Choose the branch.** PE-only → `pefile` with the specific directories parsed. Mixed formats → `lief` with per-format field mapping. APK → `androguard` with a decompression cap. Behaviour labels → `capa` run separately against its rules and signatures.
3. **Define how to validate the extractor.** Run twice over the same sample and assert byte-identical output (determinism). Feed a truncated PE and a malformed APK and assert a clean error rather than a crash or a partial vector. Feed a section declaring an oversized raw size and assert it is skipped and recorded. Compare `imphash` against an independent tool for one known sample.
4. **Name the stop condition.** Stop when the sample exceeds the size cap, when a declared uncompressed total exceeds the cap, when a section or directory claims more bytes than the file contains, when extraction raises on a malformed header, or when the parser version differs from the one used to train the model.
5. **State what counts as a working tool.** A working extractor emits one deterministic record per sample with the sample hash, the parser name and version, every requested feature, and an explicit list of skipped structures with reasons; it exits `0` on a complete extraction, `1` on a partial one, and `2` when the sample cannot be parsed at all.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `pe.get_imphash()` with the library/function order preserved | Proves the feature is comparable across samples and reproducible |
| Section entropy from `get_data()` with a size cap | Proves packing/encryption is measured without reading an attacker-declared length |
| `capa` capability list kept separate from numeric features | Proves behaviour labels and vector features are not conflated in one column |
| `AnalyzeAPK` permissions, intents, and API calls | Proves the Android vector is derived from DEX analysis, not string guessing |
| Parser name and version recorded with the record | Proves the vector is reproducible; parsers change field semantics between versions |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: trusts declared section sizes, no caps, no determinism guarantee,
# and mixes behaviour labels into the numeric vector.
import pefile

def features(path):
    pe = pefile.PE(path)
    vec = []
    for section in pe.sections:
        data = section.get_data()                       # honours attacker-declared size
        vec.append(len(set(data)) / max(len(data), 1))  # not real entropy, not bounded
    vec.append(pe.get_imphash())
    return vec
```

**Production-Grade Starter Skeleton (USE):**

```python
# feature_extract.py - Exit 0 complete, 1 partial, 2 unparseable
import hashlib
import json
import math
import pathlib
import sys

import pefile

MAX_SAMPLE_BYTES = 100 * 1024 * 1024
MAX_SECTION_BYTES = 16 * 1024 * 1024

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)

def pe_features(path: pathlib.Path) -> dict:
    size = path.stat().st_size
    if size > MAX_SAMPLE_BYTES:
        raise ValueError(f"sample exceeds cap: {size}")
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
    ])
    sections, skipped = [], []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")
        declared = int(section.SizeOfRawData)
        if declared > MAX_SECTION_BYTES:
            skipped.append({"section": name, "reason": "declared_size_over_cap", "bytes": declared})
            continue
        data = section.get_data()
        sections.append({
            "name": name,
            "raw_size": len(data),
            "entropy": shannon_entropy(data),
            "executable": bool(section.Characteristics & 0x20000000),
            "writable": bool(section.Characteristics & 0x80000000),
        })
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", "replace") if entry.dll else ""
        for imp in entry.imports:
            if imp.name:
                imports.append(f"{dll}!{imp.name.decode('utf-8', 'replace')}")
    pe.close()
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "parser": "pefile",
        "format": "pe",
        "machine": hex(pe.FILE_HEADER.Machine),
        "imphash": pe.get_imphash(),
        "imports": sorted(imports)[:500],
        "sections": sections,
        "skipped_structures": skipped,
        "has_signature": bool(getattr(pe, "DIRECTORY_ENTRY_SECURITY", None)),
    }

def main(path_str: str) -> int:
    path = pathlib.Path(path_str)
    if not path.is_file():
        sys.stderr.write(f"fatal: not a file: {path}\n")
        return 2
    try:
        record = pe_features(path)
    except (ValueError, OSError, pefile.PEFormatError) as exc:
        sys.stderr.write(f"fatal: {path.name}: {exc}\n")
        return 2
    print(json.dumps(record, sort_keys=True))
    return 1 if record["skipped_structures"] else 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: feature_extract.py <sample>\n")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
```

**Why this matters:** the section cap is checked before `get_data()`, skipped structures are reported rather than silently dropped, and the output is sorted and deterministic — so the same bytes always produce the same record, which is the precondition for using it as a model input.

## When It Is NOT This Issue

- **A sample yields an identical `imphash` to benign software** — imphash clusters by import table, so applications built from the same framework collide; it is a similarity feature, not a verdict.
- **Entropy is high on a legitimate installer** — compressed installers and packed legitimate software both show high section entropy; entropy indicates packing, not intent.
- **The extractor crashes on one sample in a batch** — a malformed or truncated header is expected in malware corpora; the parser must raise cleanly and the batch must continue.
- **A feature vector changes after a library upgrade** — parser versions change field semantics and defaults; pin versions and record them with the vector.
- **`capa` reports capabilities on a packed sample** — packed code has few recoverable features, so an empty capability list means "not analyzable statically", not "benign".

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute, load, or emulate the sample in a static extraction path.
- NEVER read a section or resource using its declared size without checking it against the file's actual length and a cap.
- NEVER present `imphash` or entropy alone as a maliciousness verdict.
- NEVER change parser versions without recording the change alongside the feature records.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Sample formats, size caps, and the downstream feature schema for `static-pe-elf-apk-feature-extractor-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The extractor, cap, or determinism check is specific and runnable (no generic 'extract features' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: static-pe-elf-apk-feature-extractor-scripting
- **Target Stack & Schema**: pefile / lief / androguard / flare-capa, all static with size and section caps
- **Safety, Scope & Exit-Code Guards**: [No execution, declared-size validation, deterministic output, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [imphash collisions, packed samples, malformed headers, parser version drift]
- **Implementation**:
  [Runnable extractor following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile feature_extract.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Signature rules over the same samples
- [`malware-config-and-string-decoder-scripting`](../malware-config-and-string-decoder-scripting/SKILL.md) - Extracts configuration and decoded strings from these binaries
- [`ole-pdf-and-office-triage-scripting`](../ole-pdf-and-office-triage-scripting/SKILL.md) - Document stage that often drops the executable analysed here
- [`volatility3-plugin-and-memory-triage-scripting`](../volatility3-plugin-and-memory-triage-scripting/SKILL.md) - Memory-side view of the same binary in execution
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Execution artefacts that corroborate a sample's presence

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `static-pe-elf-apk-feature-extractor-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-506`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 1 |
| Top sources | LAMDA (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
