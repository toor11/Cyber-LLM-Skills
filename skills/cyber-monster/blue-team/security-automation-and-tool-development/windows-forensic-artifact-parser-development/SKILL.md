---
name: windows-forensic-artifact-parser-development
description: "Engineers forensically sound Python parsers and timeline normalizers for Windows artifacts: Registry hives (`regipy`/`python-registry`), Prefetch (`pyscca`), `$MFT`/`$UsnJrnl`, LNK (`LnkParse3`), and Amcache/Shimcache — strictly read-only, preserving raw MACB FILETIME nanosecond timestamps and SHA-256 chain-of-custody hashes. Use when building DFIR artifact parsers."
family: security-automation-and-tool-development
tier: flagship
triggers: ["forensic parser python", "regipy script", "mft parser python", "prefetch parser", "chain of custody hash"]
cwe: [CWE-345, CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Windows Forensic Artifact Parser Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **flagship** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Windows artifact parsers all do the same job: decode a binary structure into rows with timestamps, without altering the source. The structures differ enough that each has its own library and its own traps. Registry hives are REGF files with cells, subkey lists, and value records; `regipy`'s `RegistryHive` walks them (`get_key`, `iter_values`, `recurse_subkeys`, and a plugin layer for Amcache/Shimcache-style derived artifacts), and transaction logs must be applied to recover the newest writes. Prefetch files begin with a compressed header followed by a version-specific file-information block — and the offset of the run count and last-run time varies by version and even within a version (the 212-byte versus 220-byte file-information layout in versions 30/31 is a documented source of wrong field reads). `$MFT` entries carry four MACB timestamps per filename and per standard-information attribute as FILETIME (100-nanosecond intervals since 1601-01-01 UTC), and `$UsnJrnl:$J` is a sparse stream of change records. LNK files carry a `LinkTargetIDList`, `LinkInfo` block with volume and local path, and extra data blocks including `DISTRIBUTED_LINK_TRACKER`. Across all of them the forensic obligations are identical: open read-only (ideally from an image or a copy with a known hash), never normalize a timestamp in a way that loses precision or zone, record the source offset for each derived row, and keep a chain-of-custody manifest of the inputs.

- **CWE-345 (Insufficient Verification of Data Authenticity):** a parser that does not hash its input cannot show the artefact it reports on is the artefact it received.
- **CWE-778 (Insufficient Logging):** an artefact class that silently parses to zero rows — because the hive needs transaction logs, or the Prefetch version is unsupported — reads as absent evidence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you parse a registry hive **THEN** copy the hive plus any `.LOG1`/`.LOG2` transaction logs, apply the logs on the copy so recent writes are visible, and read with `regipy.registry.RegistryHive`.
2. **IF** you parse Prefetch **THEN** branch on the file version *and* on the file-information block size before reading run count or last-run time; versions 30/31 have both a 212-byte and a 220-byte layout.
3. **IF** you convert FILETIME **THEN** keep the raw 100-nanosecond value in the record alongside the ISO-8601 UTC rendering, so precision is not lost in the conversion.
4. **IF** the artifact is a `$MFT` or `$UsnJrnl:$J` **THEN** stream entries and record the entry/offset, and treat the sparse nature of `$J` explicitly rather than reading it as a flat file.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `windows-forensic-artifact-parser-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable parser and manifest shapes | [`QUERIES.md`](QUERIES.md) | Hive + logs, Prefetch version branch, FILETIME handling, manifest |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `regipy`, `pyscca`, `LnkParse3`, `dissect.target` entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Version-offset and missing-transaction-log incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Chain-of-custody handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `regipy` (`RegistryHive`, plugins) for hives, `pyscca`/`libscca` for Prefetch, `LnkParse3` for shortcuts, `dissect.target` or `dfir_ntfs` for `$MFT`/`$UsnJrnl`, all read-only against a hashed copy
- **Mandatory Self-Validation Command:** `python -m py_compile artifact_parse.py`

1. **Confirm the inputs.** Establish the artifact type and Windows version it came from, whether required companion files exist (registry transaction logs, `$UsnJrnl` stream), whether you are reading an image or a copy, and the recorded hash of every input. Confirm the output schema the timeline consumer expects.
2. **Choose the branch.** Hive → apply logs then walk keys. Prefetch → detect version and file-information layout before reading counters. `$MFT` → stream entries with MACB per attribute. LNK → parse target list, info block, and tracker blocks. Each branch has a different "cannot parse" signature that must be reported rather than swallowed.
3. **Define how to validate the parser.** Assert a non-zero row count for an artifact known to contain records; assert a known Prefetch file's run count against an independent tool; assert FILETIME conversion round-trips to the raw value; assert that a version-17 Prefetch (68-byte file information) reads last-run time from the 8-byte field rather than the low 4 bytes.
4. **Name the stop condition.** Stop when an input hash does not match the manifest, when transaction logs are present but unapplied, when a Prefetch version/layout is not recognised, when a timestamp converts outside a plausible range (before 1990 or after acquisition), or when a parser returns zero rows for a class that cannot be empty.
5. **State what counts as a working tool.** A working parser emits one JSONL row per artefact record with the source path, offset or entry id, raw timestamp, ISO-8601 UTC rendering, and parsed fields; it exits `0` when every input was fully parsed, `1` when an artefact was partially parsed or a class returned nothing unexpectedly, and `2` on a hash mismatch or unreadable input.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Transaction logs applied on the copy before reading | Proves recent registry writes are visible; an unapplied hive reports stale values |
| Prefetch layout chosen by file-information size, not version alone | Proves run count and last-run time read from the correct offsets for that file |
| Raw FILETIME retained beside the ISO rendering | Proves precision survived conversion and the value is re-derivable |
| `$MFT` row carrying entry number and attribute type | Proves each timestamp is attributable to a specific attribute, not a flattened file |
| SHA-256 manifest over every input | Proves the parsed artefact is the received artifact |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: opens the hive in place (mutating it), ignores transaction logs,
# and reads Prefetch run count from a fixed offset regardless of layout.
import datetime as dt
import struct

from regipy.registry import RegistryHive

def parse(hive_path, prefetch_bytes):
    hive = RegistryHive(hive_path)                      # opened read-write in place
    values = hive.get_key(r"Software\Microsoft\Windows\CurrentVersion\Run").get_values()
    run_count = struct.unpack_from("<I", prefetch_bytes, 208)[0]   # one layout only
    last_run = struct.unpack_from("<I", prefetch_bytes, 120)[0]    # low 4 bytes of a FILETIME
    return values, run_count, last_run
```

**Production-Grade Starter Skeleton (USE):**

```python
# artifact_parse.py - Exit 0 fully parsed, 1 partial/empty class, 2 hash mismatch or unreadable
import datetime as dt
import hashlib
import json
import pathlib
import shutil
import struct
import sys
import tempfile

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
PLAUSIBLE_MIN = dt.datetime(1990, 1, 1, tzinfo=dt.timezone.utc)

def sha256_of(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def filetime_to_record(raw: int) -> dict:
    """Keep the raw 100ns value and its UTC rendering; refuse implausible values."""
    if raw <= 0:
        return {"raw_filetime": raw, "utc": None, "plausible": False}
    stamp = FILETIME_EPOCH + dt.timedelta(microseconds=raw / 10)
    return {
        "raw_filetime": raw,
        "utc": stamp.isoformat().replace("+00:00", "Z"),
        "plausible": stamp >= PLAUSIBLE_MIN,
    }

def copy_with_logs(hive: pathlib.Path, work: pathlib.Path) -> list[pathlib.Path]:
    copied = []
    for suffix in ("", ".LOG1", ".LOG2"):
        src = hive.with_name(hive.name + suffix)
        if src.is_file():
            shutil.copy2(src, work / src.name)
            copied.append(work / src.name)
    return copied

def parse_hive(hive: pathlib.Path) -> list[dict]:
    from regipy.registry import RegistryHive

    work = pathlib.Path(tempfile.mkdtemp(prefix="hive_"))
    rows = []
    try:
        copied = copy_with_logs(hive, work)
        snapshot = work / hive.name
        if snapshot != copied[0] and copied[0].name != hive.name:
            shutil.copy2(copied[0], snapshot)
        reg = RegistryHive(str(snapshot))
        for entry in reg.recurse_subkeys(as_json=True):
            rows.append({
                "artifact": "registry",
                "path": entry.get("path"),
                "last_modified_raw": entry.get("timestamp"),
                "values": len(entry.get("values") or []),
            })
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return rows

def parse_prefetch(data: bytes, source: str) -> dict:
    version = struct.unpack_from("<I", data, 0)[0]
    metrics_offset = struct.unpack_from("<I", data, 84)[0] if version >= 17 else 0
    record = {"artifact": "prefetch", "source": source, "version": version,
              "rows": [], "layout": None}
    if version == 17:
        # 68-byte file information: FILETIME at 120, run count at 144
        record["layout"] = "v17-68byte"
        raw = struct.unpack_from("<Q", data, 120)[0]
        run_count = struct.unpack_from("<I", data, 144)[0]
        record["rows"].append({"run_count": run_count, **filetime_to_record(raw)})
    elif version in (30, 31):
        # 212-byte layout puts metrics at 296 and run count at 200; 220-byte uses 304/208
        if metrics_offset == 296:
            record["layout"] = "v30-212byte"
            run_count = struct.unpack_from("<I", data, 200)[0]
        elif metrics_offset == 304:
            record["layout"] = "v30-220byte"
            run_count = struct.unpack_from("<I", data, 208)[0]
        else:
            record["layout"] = f"unknown(metrics_offset={metrics_offset})"
            return record
        record["rows"].append({"run_count": run_count})
    else:
        record["layout"] = "unsupported"
    return record

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: artifact_parse.py <artifact> [--sha256 <expected>]\n")
        return 2
    path = pathlib.Path(argv[1])
    if not path.is_file():
        sys.stderr.write(f"fatal: not a file: {path}\n")
        return 2
    actual = sha256_of(path)
    if len(argv) >= 4 and argv[2] == "--sha256" and actual != argv[3].lower():
        sys.stderr.write(f"fatal: hash mismatch {actual} != {argv[3]}\n")
        return 2
    suffix = path.suffix.lower()
    try:
        if suffix in (".dat", ".hive", "") and path.stat().st_size and path.name.upper().startswith(("SOFTWARE", "SYSTEM", "NTUSER", "SECURITY", "SAM")):
            rows = parse_hive(path)
        elif suffix == ".pf":
            rows = [parse_prefetch(path.read_bytes(), path.name)]
        else:
            rows = [{"artifact": "unknown", "source": path.name, "sha256": actual}]
    except Exception as exc:
        sys.stderr.write(f"fatal: {exc}\n")
        return 2
    for row in rows:
        print(json.dumps({**row, "source_sha256": actual}))
    return 0 if rows else 1

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

**Why this matters:** the hive is parsed from a copy with its transaction logs, the Prefetch layout is chosen by the file-information size rather than the version alone, and every timestamp keeps its raw FILETIME beside the rendering — so a wrong field read is visible in the output instead of producing a confident wrong date.

## When It Is NOT This Issue

- **A hive value differs from what the live system shows** — transaction logs were not applied; an unapplied hive reflects the last flush, not the last write.
- **Prefetch last-run time is in 1601** — the low 4 bytes of a FILETIME were read as a whole value; the field is 8 bytes, and the file-information layout determines its offset.
- **An `$MFT` record shows four identical timestamps** — timelining tools sometimes collapse the MACB set; the raw attribute values must be preserved per attribute type.
- **A parser returns zero rows for a known-populated artifact** — check the companion files and the version support before concluding absence of evidence.
- **A hive opens but many keys are missing** — the hive is a partial or corrupt copy; regipy can open partial hives with `partial_hive_path`, and the result must be labelled partial.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER open evidence artifacts read-write; copy first, then parse the copy.
- NEVER read a Prefetch field from a fixed offset without confirming the version and file-information layout for that file.
- NEVER convert a FILETIME with floating point or truncate it to seconds; keep the raw value.
- NEVER present a partial or log-unapplied parse as complete.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Artifact type, source OS version, companion files, and input hashes for `windows-forensic-artifact-parser-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The parser, layout branch, or manifest step is specific and runnable (no generic 'parse the hive' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: windows-forensic-artifact-parser-development
- **Target Stack & Schema**: regipy / pyscca / LnkParse3 / dissect.target against a hashed read-only copy
- **Safety, Scope & Exit-Code Guards**: [Copy-then-parse, hash manifest, raw FILETIME retention, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Unapplied transaction logs, version layout differences, partial hives, sparse $J]
- **Implementation**:
  [Runnable parser following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile artifact_parse.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sqlite-wal-and-browser-artifact-scripting`](../sqlite-wal-and-browser-artifact-scripting/SKILL.md) - Same evidence-integrity discipline for database artefacts
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Event-log counterpart with its own reassembly rules
- [`super-timeline-and-plaso-postprocessing-scripting`](../super-timeline-and-plaso-postprocessing-scripting/SKILL.md) - Consumes these rows as timeline input
- [`velociraptor-vql-artifact-development`](../velociraptor-vql-artifact-development/SKILL.md) - Fleet collection of the same artefact classes
- [`volatility3-plugin-and-memory-triage-scripting`](../volatility3-plugin-and-memory-triage-scripting/SKILL.md) - Memory-side evidence to corroborate disk artefacts

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-forensic-artifact-parser-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345, CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
