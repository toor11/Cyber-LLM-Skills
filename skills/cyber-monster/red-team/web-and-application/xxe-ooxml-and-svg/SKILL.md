---
name: xxe-ooxml-and-svg
description: XXE in OOXML, SVG and document formats. Covers XXE through docx, xlsx, pptx, SVG and PDF-adjacent XML entry points where uploads are parsed server-side. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["docx xxe", "xlsx xxe", "svg xxe", "ooxml xxe", "document xxe"]
cwe: [CWE-611]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-221]
related: [xxe, xxe-file-disclosure, xxe-oob-exfiltration, xxe-parser-differential-bypass]
parent: xxe
corpus_sparse: true
---

# XXE Ooxml and Svg - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Office and SVG formats are XML underneath, so an upload feature that unzips a docx, xlsx, or pptx and parses a part, or that renders an SVG, becomes an XXE entry point even though the user only uploaded a document. The decision point is the parser that reads the extracted part: a DOCTYPE placed inside word/document.xml, xl/workbook.xml, or an SVG prolog is dereferenced if that parser resolves entities. The container hides the payload from naive content inspection because the malicious bytes live in a specific zip member rather than the uploaded file's surface. Impact is the same file read and server-side fetch as raw XXE, driven through a document-processing pipeline such as a thumbnailer, a report importer, or a preview renderer. Proof is a benign marker returning or a callback arriving from a crafted document part, not from a raw XML body.

- **Precondition chain:** An upload is unzipped or rendered server-side, the XML part inside it is parsed with entity resolution on, and a feedback channel exists through the document pipeline to observe the dereference.
- **Readable differential:** A clean document is compared against one whose inner XML part declares a SYSTEM entity; a finding exists when the marker returns or a callback fires from the document pipeline, and it stops once the part parser forbids DTDs.
- **Empirical grounding:** CWE-611 anchors this leaf under OWASP Top 10:2025 A05 Injection; the leaf is marked corpus_sparse and SOURCES.md has no OOXML- or SVG-specific product advisory, so this stays at taxonomy, with the structural fix being to forbid DTDs when parsing document parts.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as document-format XXE **THEN** start at the parent class [`xxe`](../xxe/SKILL.md) (1 hop) for general triage
2. **IF** an uploaded docx, xlsx, or pptx is parsed server-side **THEN** inject a DOCTYPE into the specific part the server reads, not the container
3. **IF** the part the server reads is word/document.xml **THEN** target that zip member rather than the archive wrapper
4. **IF** the upload is an SVG that is rendered or thumbnailed **THEN** place the DOCTYPE in the SVG prolog before the svg element
5. **IF** the format is a spreadsheet **THEN** target xl/workbook.xml or a sheet part where the parser reads it
6. **IF** the pipeline reflects parsed text back **THEN** use an in-band marker and route to [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md)
7. **IF** the upload path returns nothing to the caller **THEN** use a callback and route to [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the document-part parser forbids DTDs **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Reflection is in-band on the upload response | [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) | In-band read differs from the archive-member entry point |
| The upload path is blind | [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) | A blind callback differs from document-part parsing |
| The upload filter is the real gap | [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) | Container and archive delivery is a separate invariant from XML parsing |
| Need parent class methodology | [`xxe`](../xxe/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate which document part the pipeline parses.** Determine whether the server reads word/document.xml, a spreadsheet part, or an SVG prolog, because the DOCTYPE must sit in the exact member the parser consumes.
2. **Confirm the parse happens server-side.** Verify the upload is unzipped or rendered by the server rather than only stored, since storage alone is not a parse.
3. **Record a clean-document baseline.** Upload an unmodified document and capture the pipeline's normal output or any preview it returns.
4. **Insert a benign entity into the correct part.** Repack the document with a DOCTYPE and a benign internal entity in the parsed part, confirming the entity expands in the pipeline output before any external reference.
5. **Escalate to a benign marker read or callback.** Point a SYSTEM entity at a benign local marker or an assessor host, choosing in-band reflection if the pipeline echoes text or an out-of-band callback if it is blind.
6. **Stop condition.** Halt when the pipeline either (a) returns the marker or triggers a callback from the crafted part and stops once DTDs are forbidden, (b) parses the part with entities off and shows nothing, or (c) would require reading real secrets to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign marker surfacing in the document pipeline output or a callback from a crafted document part, tied to the member you edited, plus the parser setting; a document that merely uploaded is not proof.
8. **Close with the structural fix.** Parse every extracted document part with a DTD-forbidding, entity-disabled parser, and reject documents whose parts declare a DOCTYPE. Verify by re-uploading the crafted document and seeing it rejected or inert.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A DOCTYPE inside word/document.xml returning a marker through the importer | Proves XXE via the OOXML part on a server-side document pipeline, the core case for this leaf |
| An SVG prolog DOCTYPE dereferencing when the file is thumbnailed | Proves the SVG render path parses entities, a distinct entry point from office formats |
| A SYSTEM entity in xl/workbook.xml reaching a benign marker | Proves the spreadsheet part parser resolves entities on the ingestion tier |
| The malicious bytes residing only in a zip member, not the file surface | Proves container concealment that naive content inspection misses |
| A benign internal entity expanding in a generated preview | Proves the pipeline parses the part before any external reference is tried |
| A crafted part parsed with DTDs forbidden and no dereference | Proves the hardened state, the inert non-finding for this leaf |

## Worked Contrast

**Vulnerable pattern:**

```python
import zipfile
from lxml import etree


def read_docx(path):
    with zipfile.ZipFile(path) as archive:
        xml_bytes = archive.read("word/document.xml")
    # The office part is parsed with a default parser that honours the DOCTYPE
    # smuggled inside the zip member.
    return etree.fromstring(xml_bytes)
```

**Hardened pattern:**

```python
import zipfile
import defusedxml.ElementTree as defused


def read_docx(path):
    with zipfile.ZipFile(path) as archive:
        xml_bytes = archive.read("word/document.xml")
    # defusedxml rejects any DOCTYPE in the unzipped part before it is parsed.
    return defused.fromstring(xml_bytes, forbid_dtd=True, forbid_entities=True)
```

**Why this matters:** The defect unzips the document and parses the part with a default parser that resolves a smuggled DOCTYPE. The structural control parses extracted parts with a DTD-forbidding, entity-disabled parser, so a DOCTYPE hidden in word/document.xml is rejected rather than dereferenced.

## When It Is NOT This Issue

- **Upload stored but never parsed:** a document that is saved and never unzipped or rendered server-side has no parse, so no XXE entry point exists.
- **Wrong part edited:** a DOCTYPE placed in a member the pipeline does not read, such as a thumbnail or a core-properties part it ignores, will not dereference and is not a finding.
- **DTD forbidden in the part parser:** a pipeline that parses parts with DTDs disabled rejects the smuggled declaration, which is the control working.
- **Client-side render only:** an SVG that is only rendered in the victim's browser and never parsed server-side is a client-side concern, not server XXE.
- **Image rasterised without XML parsing:** a converter that treats SVG as a raster image without an XML entity-resolving parser does not dereference entities.
- **Marker from document text:** a marker that appears because it was in the document body, not because an entity dereferenced, is not proof of XXE.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xxe-ooxml-and-svg` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xxe-ooxml-and-svg` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xxe-ooxml-and-svg
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xxe`](../xxe/SKILL.md) - Web and Application (core)
- [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) - Web and Application (leaf)
- [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) - Web and Application (leaf)
- [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xxe-ooxml-and-svg` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
