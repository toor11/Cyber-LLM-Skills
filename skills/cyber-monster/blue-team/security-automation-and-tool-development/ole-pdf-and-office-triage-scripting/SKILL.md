---
name: ole-pdf-and-office-triage-scripting
description: "Builds non-executing malicious document triage scripts using `oletools` (`olevba`, `oleid`) and `pdfid`/`pypdf`: extracting VBA macro streams, auto-exec triggers, external template URLs (`TargetMode=\"External\"`), and JavaScript/OpenAction PDF objects safely on disk/memory buffers. Use when automating document-lure triage."
family: security-automation-and-tool-development
tier: leaf
triggers: ["olevba python script", "maldoc triage script", "pdfid parser", "external template detector"]
cwe: [CWE-506]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# OLE PDF and Office Triage Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Document triage is the discipline of reading a file's internal structure without ever letting its logic run. An Office document is either an OLE compound file (legacy `.doc`/`.xls`) or an OpenXML ZIP (`.docm`/`.xlsm`) whose macros live in a `vbaProject.bin` stream; `oletools.olevba.VBA_Parser` locates those streams across formats and exposes `detect_vba_macros()`, `analyze_macros()` (returning `(type, keyword, description)` tuples for auto-exec, suspicious, IOC, and obfuscated-string findings), and `get_vba_code_all_modules()`. `oleid` summarizes risk indicators rather than extracting code. On the PDF side the dangerous constructs are structural: `/OpenAction` and `/AA` (actions triggered on open), `/JavaScript` and `/JS`, `/Launch`, and `/EmbeddedFile`. `pdfid` counts those object types without rendering, and `pypdf` can walk the object tree for detail. The safety rule is absolute: nothing in triage evaluates macro code, opens the document in an Office application, or lets a PDF reader parse it. Two more constraints shape the tooling. `TargetMode="External"` in a document's settings points at a remote template — a live URL that fetches and executes content — so it must be extracted and defanged, never fetched. And the extraction itself needs a size cap: a ZIP bomb or a deeply nested OLE structure can consume memory before a single macro is read.

- **CWE-506 (Embedded Malicious Code):** the document is a delivery vehicle for code the user is invited to enable; triage exists to characterise that code without executing it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the file is an Office document **THEN** open it with `VBA_Parser(path)` (bytes accepted via `data=`), call `detect_vba_macros()` then `analyze_macros()`, and treat `detect_autoexec` as superseded — `analyze_macros()` returns the auto-exec findings directly.
2. **IF** the document may reference a remote template **THEN** extract the `TargetMode="External"` URL from the settings relationship and defang it; never fetch it.
3. **IF** the file is a PDF **THEN** count `/OpenAction`, `/JS`, `/JavaScript`, `/Launch`, and `/EmbeddedFile` with `pdfid`-style scanning, then use `pypdf` to inspect specific objects rather than rendering.
4. **IF** the input is untrusted **THEN** enforce an uncompressed-size cap and a nesting bound before parsing; a document that expands past the cap is a finding, not a parse failure to retry.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `ole-pdf-and-office-triage-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable triage shapes | [`QUERIES.md`](QUERIES.md) | Macro extraction, auto-exec findings, PDF keyword scan, size guards |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `oletools`, `pdfid`, `pypdf` entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Remote-template and PDF-action incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Mailbox/document-scope handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `oletools` (`olevba.VBA_Parser`, `oleid`), `pdfid`-style keyword scanning, and `pypdf` for object-level inspection, all operating on stored bytes with size caps
- **Mandatory Self-Validation Command:** `python -m py_compile doc_triage.py`

1. **Confirm the inputs.** Identify the container format, the file size and (for ZIP containers) the declared uncompressed total, whether the document is macro-enabled by extension, and the report fields the SOC needs. Confirm triage runs on a copy with the hash recorded.
2. **Choose the branch.** OLE/OpenXML with macros → `VBA_Parser` extraction plus `analyze_macros()`. OpenXML without macros but with relationships → check for external template targets. PDF → structural keyword scan then targeted object reads. Unknown container → hash and type-detect before choosing a parser.
3. **Define how to validate the triage.** Fixtures: a macro-enabled document with a known auto-exec trigger (must be flagged), the same document with macros stripped (must not be flagged), a document with an external template relationship (URL must be extracted and defanged), and a PDF with `/OpenAction` plus `/JS` (must be counted). Assert peak memory against a zip-bomb fixture.
4. **Name the stop condition.** Stop when the uncompressed size exceeds the cap, when the parser raises on an unsupported format, when a macro stream is present but unreadable (report as unreadable, never as clean), or when an external URL would require a fetch to characterise.
5. **State what counts as a working tool.** A working triage exits `0` when every artefact was characterised, `1` when suspicious constructs were found (if used as a detector), and `2` on an unreadable or oversized file. Its report contains macro findings, auto-exec keywords, defanged external URLs, PDF construct counts, and the file hash — and no executed code.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `VBA_Parser.detect_vba_macros()` plus `analyze_macros()` tuples | Proves macro presence and characterises triggers/obfuscation without execution |
| `TargetMode="External"` relationship target | Proves the document pulls remote content, which is a live payload path |
| `/OpenAction` and `/JS` counts from a structural scan | Proves the PDF has auto-triggered script objects before any renderer is involved |
| Declared uncompressed size versus cap | Proves a decompression bomb is refused rather than expanded |
| File SHA-256 recorded with the findings | Proves the report refers to a specific artefact |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: extracts every stream with no size cap, uses the deprecated
# auto-exec helper, and fetches the external template URL to "check" it.
import io
import zipfile

import requests
from oletools.olevba import VBA_Parser

def triage(path):
    with zipfile.ZipFile(path) as zf:
        blobs = {n: zf.read(n) for n in zf.namelist()}      # unbounded expansion
    parser = VBA_Parser(path, data=open(path, "rb").read())
    for _fn, _sp, _vn, code in parser.extract_macros():
        print(code)
    for url in parser.detect_autoexec():                    # deprecated helper
        requests.get(url, timeout=5)                        # announces the analyst
```

**Production-Grade Starter Skeleton (USE):**

```python
# doc_triage.py - Exit 0 characterised, 1 suspicious, 2 unreadable/oversized
import hashlib
import json
import pathlib
import re
import sys
import zipfile

from oletools.olevba import VBA_Parser

MAX_UNCOMPRESSED = 200 * 1024 * 1024
PDF_KEYWORDS = (b"/OpenAction", b"/AA", b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile")
URL_RE = re.compile(rb"(?:https?|file)://[^\s\"'<>\x00]+")

def defang(url: str) -> str:
    return url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")

def check_zip_bomb(path: pathlib.Path) -> tuple[bool, int]:
    try:
        with zipfile.ZipFile(path) as zf:
            total = sum(info.file_size for info in zf.infolist())
            return total > MAX_UNCOMPRESSED, total
    except zipfile.BadZipFile:
        return False, 0

def triage_office(path: pathlib.Path) -> dict:
    report = {"kind": "office", "macros": [], "autoexec": [], "external_targets": []}
    parser = VBA_Parser(str(path))
    try:
        if parser.detect_vba_macros():
            for kind, keyword, description in parser.analyze_macros():
                if kind == "AutoExec":
                    report["autoexec"].append({"keyword": keyword, "note": description})
                else:
                    report["macros"].append({"type": kind, "keyword": str(keyword)[:120]})
        if path.suffix.lower() in (".docx", ".docm", ".dotm", ".xlsx", ".xlsm"):
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if not name.endswith(".rels"):
                        continue
                    for match in URL_RE.findall(zf.read(name)):
                        decoded = match.decode("utf-8", "replace")
                        if "TargetMode" in decoded or "External" in decoded or "://" in decoded:
                            report["external_targets"].append(defang(decoded))
    finally:
        parser.close()
    return report

def triage_pdf(path: pathlib.Path) -> dict:
    raw = path.read_bytes()
    counts = {kw.decode(): raw.count(kw) for kw in PDF_KEYWORDS}
    urls = [defang(u.decode("utf-8", "replace")) for u in URL_RE.findall(raw)]
    return {"kind": "pdf", "constructs": counts, "urls": sorted(set(urls))[:50]}

def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: doc_triage.py <document>\n")
        return 2
    path = pathlib.Path(sys.argv[1])
    if not path.is_file():
        sys.stderr.write(f"fatal: not a file: {path}\n")
        return 2
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    bomb, total = check_zip_bomb(path)
    if bomb:
        print(json.dumps({"sha256": digest, "verdict": "refused", "reason": "uncompressed_size",
                          "uncompressed_bytes": total}))
        return 1
    try:
        report = triage_pdf(path) if path.suffix.lower() == ".pdf" else triage_office(path)
    except Exception as exc:
        print(json.dumps({"sha256": digest, "verdict": "unreadable", "error": str(exc)}))
        return 2
    report["sha256"] = digest
    print(json.dumps(report, indent=2))
    suspicious = bool(report.get("autoexec") or report.get("external_targets")) or \
        any(count for count in report.get("constructs", {}).values() if count)
    return 1 if suspicious else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** the size cap is checked before any expansion, `analyze_macros()` replaces the deprecated helper, external template targets are extracted and defanged without a request, and every verdict carries the file hash so the report refers to one specific artefact.

## When It Is NOT This Issue

- **A macro-enabled document has no macros according to the parser** — the file may be encrypted or the macro stream corrupted; "unreadable" is not "clean", so report the distinction.
- **A PDF has `/JS` but nothing happens when opened** — the object may be unreachable from `/OpenAction`; a keyword count is not evidence of execution, and the object graph has to be followed.
- **`detect_vba_macros()` returns False for a PowerPoint 97-2003 file** — that format stores macros differently; absence of detection for that container is a parser limitation, not proof of no macros.
- **`analyze_macros()` reports "VBA obfuscated Strings" on a legitimate document** — obfuscated strings appear in benign macros too; weigh against auto-exec triggers and external targets.
- **An external relationship appears in a document that never uses it** — relationships can be stale; corroborate with the settings reference before calling it a remote-template lure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute, open, or render the document under triage; extraction is static.
- NEVER fetch a URL found in a document, including external template targets.
- NEVER present "no macros detected" as "not malicious"; it means no macros were found by this parser in this container.
- NEVER parse an unbounded ZIP or OLE structure without a size cap.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Container format, size/uncompressed total, and required report fields for `ole-pdf-and-office-triage-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The extractor, cap, or keyword scan is specific and runnable (no generic 'inspect the macro' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: ole-pdf-and-office-triage-scripting
- **Target Stack & Schema**: oletools VBA_Parser + pdfid-style keyword scan + pypdf object inspection, all static with size caps
- **Safety, Scope & Exit-Code Guards**: [No execution or render, no URL fetch, uncompressed cap, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Encrypted/corrupt macro streams, unreachable PDF objects, format-specific macro storage, stale relationships]
- **Implementation**:
  [Runnable triage script following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile doc_triage.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`phishing-email-and-header-triage-automation`](../phishing-email-and-header-triage-automation/SKILL.md) - Extracts the attachments this script analyses
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Signature coverage for the document families seen here
- [`malware-config-and-string-decoder-scripting`](../malware-config-and-string-decoder-scripting/SKILL.md) - Decodes the strings the macros reference
- [`static-pe-elf-apk-feature-extractor-scripting`](../static-pe-elf-apk-feature-extractor-scripting/SKILL.md) - Analyses the dropped executable, statically

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ole-pdf-and-office-triage-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-506`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
