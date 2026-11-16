---
name: file-upload-and-webshell-polyglot-and-archive
description: Polyglot and archive upload payloads. Covers image and document polyglots that pass validation yet execute, plus zip, tar and SVG payloads and archive traversal on extraction. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["polyglot upload", "image polyglot", "zip slip", "svg upload", "archive upload"]
cwe: [CWE-434]
owasp: [A04:2021]
attack: [T1505]
capec: [CAPEC-1]
related: [file-upload-and-webshell, file-upload-and-webshell-extension-and-mime-bypass, file-upload-and-webshell-config-and-htaccess-abuse, file-upload-and-webshell-filename-and-path-abuse]
parent: file-upload-and-webshell
---

# File Upload and Webshell Polyglot and Archive - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)

## Mechanism and Preconditions

This variant exploits a file that is simultaneously valid in two formats, or an archive whose members reconstitute into dangerous files when the server unpacks them. A polyglot satisfies an image or document parser with correct magic bytes and a decodable structure while also carrying bytes a second interpreter will execute, so a validator that only checks the first format accepts it. An archive upload passes as a single inert container, but on extraction a member carries a traversal path, an absolute path, or a symlink that writes outside the extraction root, or an SVG whose embedded script runs when rendered. The security decision is whether validation inspects the format the runtime will actually act on, including after extraction. Confirmation is that a member or second-format interpretation lands a benign marker in a context the single-format validator never examined.

- **Precondition chain:** the upload is validated against one format while a second interpreter or an extraction step acts on it, the second interpretation carries attacker-chosen content or paths, the extraction or rendering happens server-side, and the resulting artefact is reachable or executed.
- **Readable differential:** an archive or document whose first-format view is benign versus the same artefact whose second-format or extracted view carries a marker; a finding exists when the extracted or alternate-format view appears where the validator never looked, and it closes when extraction is sandboxed with path and symlink checks.
- **Empirical grounding:** CWE-434. SOURCES.md anchors the archive side with CVE-2025-3445 (mholt/archiver zip-slip), CVE-2025-4748 (Erlang/OTP `zip:unzip` absolute-path traversal), CVE-2025-55188 (7-Zip symlink extraction arbitrary write), and GHSA-94vh-gphv-8pm8 (Rust `zip` symlink traversal); these are the 2025 cases where an accepted archive reconstitutes into files outside the extraction root.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a dual-format or archive-extraction case **THEN** start at parent class [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) first (1 hop)
2. **IF** the artefact is an archive the server extracts server-side **THEN** test a benign member with a traversal or absolute path before any content probe
3. **IF** an archive member is a symlink pointing outside the extraction root **THEN** confirm whether the extractor preserves symlinks
4. **IF** the upload is an SVG or document whose embedded script runs on render **THEN** route the browser-execution angle to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md)
5. **IF** the container is OOXML or another XML-based document **THEN** route the XML parser angle to [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md)
6. **IF** the extraction traversal is a general archive-handling flaw **THEN** route to [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)
8. **IF** validation inspects every format and extraction is sandboxed with path and symlink checks **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A member escapes the extraction root by path or symlink | [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md) | Invariant is extraction-member containment, not upload-time format validation |
| The container is an XML-based document parsed server-side | [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) | Invariant is XML entity and parser handling inside the document |
| An SVG or document script executes when rendered to a user | [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) | Invariant is browser-context script execution, not server-side storage |
| Need parent class methodology | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine which parsers touch the artefact.** Read the pipeline to see whether the upload is validated by an image or document parser, extracted by an archive library, re-encoded, or rendered. List every interpreter that acts on the bytes, because the validator only covers one.
2. **Classify the dual-interpretation surface.** A format polyglot, an archive member with a traversal or absolute path, a preserved symlink, or an embedded-script document. Each reconstitutes in a different place and needs a different marker.
3. **Record a single-format baseline.** Upload a plain file valid and benign in the one format the validator checks, and confirm it is accepted and stored or extracted into the intended location only.
4. **Introduce one second-format element.** Add a single benign marker in the second interpretation: an archive member whose path targets a marker location, a symlink to a readable marker, or an image with a benign token a second parser would surface, keeping the first-format view valid.
5. **Observe the second interpretation's result.** Check the extraction output directory, the rendered document, or the alternate-format fetch for the marker, comparing against the single-format baseline that lacked it.
6. **Stop condition.** Stop when the second interpretation either (a) places or runs the benign marker in a location the single-format validator never inspected, confirming the dual-format gap, (b) is contained because extraction is sandboxed and only the validated format is acted on, or (c) would require writing a functional payload outside the root or executing real script to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign marker reconstituted by the second interpreter in a context the validator did not examine, for example an extracted member landing outside the extraction directory, tied to the parser that acted on it. A valid polyglot stored but never second-interpreted is not proof.
8. **Attribute the reconstitution step.** Name whether the gap is in the archive extractor, the XML parser, or the renderer, so the fix targets the stage that acted unseen.
9. **Close with the structural fix and verify.** Validate and re-encode every format the pipeline acts on, extract archives in a sandbox that rejects absolute paths, traversal, and symlinks and confines members to the extraction root, and strip active content from documents, then replay the polyglot and archive markers.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A file with valid image magic bytes that also parses as a second format | Proves a polyglot that satisfies the first-format validator while carrying a second interpretation |
| An archive member whose stored path contains `../` or an absolute path | Proves an extraction-time traversal the container-level check missed |
| An archive member that is a symlink to a location outside the root | Proves a symlink-extraction write primitive as in the 7-Zip and Rust zip cases |
| An SVG with an embedded script element accepted as an image | Proves active content that executes when the document is rendered to a user |
| An extraction step that writes members before validating their paths | Proves reconstitution happens ahead of any containment check |
| A re-encode or flatten step applied to accepted images | Proves a control that collapses the artefact to one format and drops the second |
| An extractor that rejects absolute paths, traversal, and symlinks | Proves members are confined to the extraction root, closing the archive surface |

## Worked Contrast

**Vulnerable pattern:**

```python
import zipfile, os

def unpack(archive_path, dest_dir):
    # Trusts member names: '../' or absolute paths escape dest_dir on extract
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.namelist():
            target = os.path.join(dest_dir, member)
            with open(target, "wb") as fh:
                fh.write(zf.read(member))
```

**Hardened pattern:**

```python
import zipfile, os

def unpack(archive_path, dest_dir):
    root = os.path.realpath(dest_dir)
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.infolist():
            if (member.external_attr >> 28) == 0xA:       # reject symlink members
                raise ValueError("symlink member refused")
            target = os.path.realpath(os.path.join(root, member.filename))
            if os.path.commonpath([target, root]) != root:
                raise ValueError("member escapes extraction root")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(zf.read(member))
```

**Why this matters:** The defective extractor joins each member name onto the destination and writes it, so a `../` or absolute member path lands outside the directory; the fixed extractor refuses symlink members and verifies each resolved member path stays inside the extraction root before writing, so no member can reconstitute outside the sandbox.

## When It Is NOT This Issue

- **Re-encoded to one format:** an upload flattened to a canonical image on accept carries no surviving second-format payload.
- **Sandboxed extraction with path checks:** an extractor that confines members to the root and rejects symlinks defeats zip-slip and absolute-path members.
- **Archive never extracted server-side:** a container stored and handed back to the user without server-side unpacking has no reconstitution step.
- **SVG served as attachment:** an SVG returned with `Content-Disposition: attachment` and never rendered in-origin does not execute its script.
- **Polyglot stored but single-interpreted:** a dual-format file only the validated parser ever reads is inert in the second format.
- **Document active content stripped:** a sanitiser that removes scripts and external references from documents neutralises the embedded-script path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `file-upload-and-webshell-polyglot-and-archive` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `file-upload-and-webshell-polyglot-and-archive` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: file-upload-and-webshell-polyglot-and-archive
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-434 | Mapping: T1505]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) - Blue Detection/Defense Counterpart
- [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) - Web and Application (core)
- [`file-upload-and-webshell-extension-and-mime-bypass`](../file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `file-upload-and-webshell-polyglot-and-archive` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-434, T1505`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/osv (3), CYBER_CPT/gh_advisories (3), ctf-solver-dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
