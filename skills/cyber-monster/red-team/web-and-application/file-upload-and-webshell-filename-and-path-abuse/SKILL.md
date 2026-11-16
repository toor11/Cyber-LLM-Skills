---
name: file-upload-and-webshell-filename-and-path-abuse
description: Filename and destination path abuse. Covers traversal in filenames, overwriting existing files, race between write and validation, and predictable storage paths for later execution. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["filename traversal upload", "upload path traversal", "upload overwrite", "upload race"]
cwe: [CWE-434]
owasp: [A04:2021]
attack: [T1505]
capec: [CAPEC-1]
related: [file-upload-and-webshell, file-upload-and-webshell-extension-and-mime-bypass, file-upload-and-webshell-config-and-htaccess-abuse, file-upload-and-webshell-polyglot-and-archive]
parent: file-upload-and-webshell
---

# File Upload and Webshell Filename and Path Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)

## Mechanism and Preconditions

This variant accepts that the file content may be fine; the defect is that the destination path is built from the submitted filename without canonicalisation, so the attacker controls where the bytes land or what they overwrite. A `../` sequence in the filename escapes the upload directory into an executable or sensitive location, a chosen name overwrites an existing file such as a configuration or another user's artefact, a predictable storage path lets the file be located and triggered later, and a race between the temporary write and the validation or move lets the file be used before the checks complete. The security decision is the canonicalisation and uniqueness of the stored path. Confirmation is that an uploaded file is retrievable from a path the attacker selected rather than the one the application intended.

- **Precondition chain:** the stored path is derived from the client filename, the application does not canonicalise or randomise that name, the resulting path can escape the intended directory or collide with an existing file, and the chosen location is reachable or consumed before validation completes.
- **Readable differential:** a benign filename stored at the intended path versus a traversing or colliding filename; a finding exists when the file is retrievable from the attacker-chosen path or overwrites a non-owned file, and it closes when the server ignores the client name and stores under a canonical random name.
- **Empirical grounding:** CWE-434 with a filesystem-canonicalisation defect. SOURCES.md anchors this with CVE-2025-6204 and CVE-2025-6205 (DELMIA Apriso), where upload filenames were not canonicalised before the destination path was built; it is the 2025 instance of the stored-name control failing independently of any type check.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a stored-name canonicalisation defect **THEN** start at parent class [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) first (1 hop)
2. **IF** the submitted filename reaches the destination path unmodified **THEN** test a traversal sequence against a benign marker path before anything else
3. **IF** the application lets a chosen name overwrite an existing file **THEN** scope the overwrite target and confirm it is not the caller's own file
4. **IF** the storage path is predictable from the filename or a counter **THEN** record the path formula so later retrieval is deterministic
5. **IF** there is a window between the temporary write and validation or move **THEN** route the time-of-check timing to [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md)
6. **IF** the traversal is really a general filesystem read or write primitive **THEN** route to [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)
8. **IF** the server stores under a server-generated canonical name and ignores the client path **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The filename traversal is a general filesystem read or write primitive | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | Invariant is path canonicalisation beyond the upload feature |
| The defect is the window between write and validation | [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) | Invariant is atomicity of check and use, not the name itself |
| The path is chosen during archive extraction rather than upload | [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md) | Invariant is extraction-member path containment |
| Need parent class methodology | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Trace how the destination path is built.** Read the handler to see whether the stored path concatenates the client filename, a user-chosen directory, or a predictable counter. Name the exact variable the attacker controls in the path.
2. **Classify the stored-name defect.** Traversal in the filename, overwrite of an existing file, a predictable path for later retrieval, or a check-to-use race. Each has a different proof and a different fix.
3. **Record an intended-path baseline.** Upload a benign file with an ordinary name, note the exact URL or path it lands at, and confirm it matches the application's documented storage scheme.
4. **Submit one canonicalisation probe.** Put a single traversal sequence, a colliding name, or a predictable-path candidate in the filename while keeping the content benign, and observe where the bytes land relative to the baseline path.
5. **Retrieve from the attacker-chosen path.** Fetch the file from the location the probe targeted rather than the intended one, confirming the stored path followed the submitted name.
6. **Stop condition.** Stop when retrieval either (a) succeeds from the attacker-selected path or the overwrite changed a file the caller does not own, confirming the stored name is not canonicalised, (b) fails because the server stored under a canonical name, or (c) would require overwriting real production data or another user's live file to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign file retrievable from a path the attacker chose, or a benign overwrite of a non-owned, non-production marker, tied to the filename variable that reached the path builder. A 200 upload whose file lands at the canonical path is not proof.
8. **Separate name control from execution.** Note whether the chosen path is also an execution context, which may chain into the configuration or extension siblings, versus a pure file-write primitive.
9. **Close with the structural fix and verify.** Discard the client filename, store under a server-generated random name in a fixed directory, resolve and verify the final real path stays inside that directory, and make validation and move atomic, then replay the traversal and overwrite probes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| The client filename concatenated into the destination path | Proves the stored path is attacker-influenced on the upload handler |
| A `../` sequence in the filename resolving above the upload directory | Proves missing canonicalisation of the stored name into a real path |
| A chosen name overwriting an existing non-owned file | Proves a write primitive against files the caller should not control |
| A predictable storage path derived from a counter or the name | Proves an attacker can locate the stored file for later retrieval or execution |
| A window between the temporary write and validation or move | Proves a time-of-check-to-time-of-use race around the stored file |
| A server-generated random name in a fixed directory | Proves the stored path ignores the client name, closing this variant |
| A post-store real-path check confined to the upload root | Proves traversal is rejected after canonicalisation |

## Worked Contrast

**Vulnerable pattern:**

```python
import os

UPLOAD_DIR = "/var/www/html/uploads"

def store(filename, data):
    # Client filename flows straight into the path; '../' escapes the directory
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest
```

**Hardened pattern:**

```python
import os, uuid

UPLOAD_DIR = "/srv/uploads"

def store(filename, data):
    name = uuid.uuid4().hex + os.path.splitext(filename)[1][:5]    # random name, bounded ext
    dest = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if os.path.commonpath([dest, UPLOAD_DIR]) != UPLOAD_DIR:
        raise ValueError("path escapes upload root")
    with open(dest, "xb") as fh:                                   # exclusive create, no overwrite
        fh.write(data)
    return dest
```

**Why this matters:** The defective store concatenates the client filename, so a traversal sequence or a chosen name writes outside the directory or overwrites an existing file; the fixed store assigns a server-generated random name, verifies the resolved real path stays inside the upload root, and creates the file exclusively, so it cannot escape the directory or clobber another file.

## When It Is NOT This Issue

- **Server-generated names:** a handler that discards the client filename and stores under a random name removes attacker control of the path.
- **Post-canonicalisation containment check:** a resolved real path verified to stay inside the upload root defeats traversal even when the raw name contains `../`.
- **Exclusive-create store:** an exclusive-create write that refuses to overwrite closes the clobber variant.
- **Caller-only path:** an overwrite confined to the caller's own isolated area with no shared or system file reachable is not cross-user impact.
- **Atomic check-and-move:** a validate-then-rename that is atomic removes the race window.
- **Non-served destination:** a chosen path outside any document root yields a file write with no execution or retrieval surface.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `file-upload-and-webshell-filename-and-path-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `file-upload-and-webshell-filename-and-path-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: file-upload-and-webshell-filename-and-path-abuse
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
- [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `file-upload-and-webshell-filename-and-path-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-434, T1505`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/vulhub (3), CYBER_CPT/osv (2), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
