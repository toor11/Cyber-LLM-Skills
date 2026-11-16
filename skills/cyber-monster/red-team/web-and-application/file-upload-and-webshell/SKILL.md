---
name: file-upload-and-webshell
description: "Bypasses file upload validation to achieve web shell execution: extension and MIME tricks, magic-byte spoofing, content-type confusion, filename traversal, archive and polyglot payloads, and .htaccess or config abuse. Use when an application accepts uploaded files reachable by the web server."
family: web-and-application
tier: core
triggers: ["file upload", "upload bypass", "webshell", "web shell", "unrestricted upload", "multipart bypass"]
cwe: [CWE-434]
owasp: [A04:2021]
attack: [T1505]
capec: [CAPEC-1]
related: [file-upload-and-webshell-extension-and-mime-bypass, file-upload-and-webshell-config-and-htaccess-abuse, file-upload-and-webshell-polyglot-and-archive, sql-injection]
---

# File Upload and Webshell - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)

## Mechanism and Preconditions

This class turns an upload feature into code execution by making a file land where the web server interprets it as a program rather than store it as inert data. The security decision spans four stages that can each be defeated independently: what the validator believes the type is, what name and directory the file is stored under, whether that directory is configured to execute, and whether an archive or polyglot reconstitutes into something executable after the server accepts it. The attacker drives one stage at a time until an uploaded artefact is both reachable by URL and handled by an interpreter. The gain is server-side execution in the web root; confirmation is a benign uploaded marker that the server evaluates rather than returns verbatim, proving the stored file sits in an execution context.

- **Precondition chain:** the application accepts an uploaded file, the file is stored where the web server can reach it by URL, at least one of the type, name, location, or content controls can be bypassed, and the storage directory is handled by an interpreter rather than served as static bytes.
- **Readable differential:** the same upload as an inert sample versus a benign marker whose server-evaluated output differs from its stored bytes; a finding exists when the fetched result shows evaluation, and it closes when the file is served verbatim from a non-executing store.
- **Empirical grounding:** CWE-434 Unrestricted Upload of File with Dangerous Type. SOURCES.md anchors the 2025 instances across the four child surfaces: GHSA-hq96-gvmx-qrwp (WeGIA MIME-only check beaten by XLSX magic bytes, a bypass of CVE-2025-22133) for type confusion, CVE-2025-6204 and CVE-2025-6205 (DELMIA Apriso filename non-canonicalisation) for stored-name abuse, and CVE-2025-3445 (mholt/archiver zip-slip) for extraction-time reconstitution.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is specifically a validator that believes the wrong type **THEN** switch to [`file-upload-and-webshell-extension-and-mime-bypass`](../file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) (1 hop)
2. **IF** the target is specifically an extracted configuration file changing how a directory executes **THEN** switch to [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) (1 hop)
3. **IF** the target is specifically one artefact valid in two formats or an archive that reconstitutes on extraction **THEN** switch to [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) (1 hop)
4. **IF** the target is specifically the canonicalisation of the stored filename or path **THEN** switch to [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) (1 hop)
5. **IF** the uploaded file is stored outside the web root and served through a download handler **THEN** confirm whether the handler ever passes the bytes to an interpreter before claiming execution
6. **IF** the upload is an SVG or XML document rendered in a browser context **THEN** route the client-side execution angle to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md)
7. **IF** a confirmed shell needs interaction or tasking **THEN** hand off to [`webshell-management-and-interaction`](../webshell-management-and-interaction/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)
9. **IF** stored bytes are served verbatim from a non-executing location and no child bypass reaches an interpreter **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The artefact is an archive that writes outside the extraction root | [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md) | Invariant is extraction-path containment, not upload-time type validation |
| Execution is already proven and needs tasking | [`webshell-management-and-interaction`](../webshell-management-and-interaction/SKILL.md) | Invariant shifts to post-exploitation interaction, out of this detection scope |
| The filename carries traversal that lands the file outside the intended store | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | Invariant is filesystem canonicalisation of the destination path |
| Target matches `file-upload-and-webshell-extension-and-mime-bypass` | [`file-upload-and-webshell-extension-and-mime-bypass`](../file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `file-upload-and-webshell-config-and-htaccess-abuse` | [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `file-upload-and-webshell-polyglot-and-archive` | [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `file-upload-and-webshell-filename-and-path-abuse` | [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the upload handler and classify its four controls.** Read the server code for the type check (extension, MIME, magic bytes, re-encoding), the destination naming and directory logic, the directory's execution configuration, and any post-upload extraction. Name which stage each control covers.
2. **Determine the storage location and whether it is interpreted.** Find the URL that maps to the stored file and whether that path is handled by PHP, ASP.NET, or JSP, or served as static bytes. An upload that cannot be reached and interpreted is not yet a finding.
3. **Pick the single stage to probe from the evidence.** If the validator trusts a client MIME, target type belief; if it trusts the submitted name, target stored-name canonicalisation; if the directory executes any extension, target configuration; if the server extracts archives, target reconstitution. Choose where the code is weakest.
4. **Record an inert-upload baseline.** Upload a plain, correctly typed sample, fetch it, and confirm the server returns the bytes verbatim. This is the reference the marker probe must diverge from.
5. **Upload a benign evaluation marker, not a shell.** Use a file whose only effect is to emit a fixed token when interpreted, fetch its URL, and compare the response to the stored bytes.
6. **Stop condition.** Stop when the fetched marker either (a) returns evaluated output instead of its source bytes, confirming an execution context, (b) is returned verbatim or blocked by a control you can name, or (c) would require uploading a functional shell or command runner to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign marker whose fetched output differs from its stored source because the server evaluated it, tied to the reachable URL and the stage that let it land there. A 200 on the upload, or a stored file served as text, is not proof.
8. **Route the confirmed stage to its child skill.** Hand type confusion, configuration abuse, polyglot or archive, or filename canonicalisation to the matching child for depth and remediation vocabulary.
9. **Close with the structural fix and verify.** Store uploads outside the web root under server-generated names, serve them through a handler that never interprets them, validate type by content and re-encode where possible, and disable execution in the upload directory, then re-fetch the marker to confirm it is returned verbatim.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A client-supplied Content-Type or extension accepted as the type of record | Proves the validator trusts a declared type rather than file content, on any upload stack |
| The stored file reachable at a predictable URL under the web root | Proves the upload lands in a location the web server will route to |
| The upload directory configured to run a scripting handler | Proves an execution context exists for whatever lands there, independent of the validator |
| A benign marker whose fetched output differs from its stored bytes | Proves the server evaluated the file rather than serving it, the core confirmation on this class |
| Server-side re-encoding that strips appended bytes from images | Proves a compensating control that neutralises trailing-payload polyglots |
| An archive-extraction step that writes files under the web root | Proves a reconstitution surface where extracted members may become executable |
| A download handler that sets Content-Disposition and never interprets bytes | Proves an inert serving path that defeats execution even with weak validation |

## Worked Contrast

**Vulnerable pattern:**

```python
import os

UPLOAD_DIR = "/var/www/html/uploads"

def save_upload(file, declared_type):
    # Trusts the client Content-Type and the submitted filename; stores in the web root
    if declared_type.startswith("image/"):
        dest = os.path.join(UPLOAD_DIR, file.filename)
        with open(dest, "wb") as fh:
            fh.write(file.read())
        return "/uploads/" + file.filename
    raise ValueError("not an image")
```

**Hardened pattern:**

```python
import os, uuid

UPLOAD_DIR = "/srv/uploads"              # outside the web root, no interpreter mapped
ALLOWED = {"image/png": ".png", "image/jpeg": ".jpg"}

def save_upload(file, sniffed_type):
    ext = ALLOWED.get(sniffed_type)      # type decided by content sniffing, not the client
    if ext is None:
        raise ValueError("unsupported type")
    name = uuid.uuid4().hex + ext        # server-generated name, no client string
    with open(os.path.join(UPLOAD_DIR, name), "wb") as fh:
        fh.write(file.read())
    return "/files/" + name              # served through a non-interpreting handler
```

**Why this matters:** The defective handler trusts the declared type and the client filename and writes into an executable web directory, so a renamed script lands in an interpreter's reach; the fixed handler decides the type from sniffed content, assigns a server-generated name, and stores outside the web root behind a handler that only streams bytes, so no uploaded file can be executed.

## When It Is NOT This Issue

- **Stored outside the web root:** files written to a directory with no URL mapping and streamed by a handler cannot be reached and interpreted.
- **Server re-encodes the image:** a pipeline that re-encodes uploads to a canonical image discards appended code, so a polyglot does not survive.
- **Directory execution disabled:** an upload folder served as static bytes with scripting handlers turned off is inert even with a weak validator.
- **Caller-only artefact:** a file visible only in the uploader's own private area with no execution context is not a finding.
- **Content-disarm quarantine:** a confirmed content-disarm or antivirus step that neutralises active content before storage is a compensating control.
- **200 response without a reachable URL:** a successful upload whose stored path is never served is not evidence of execution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `file-upload-and-webshell` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `file-upload-and-webshell` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: file-upload-and-webshell
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-434 | Mapping: T1505]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) - Blue Detection/Defense Counterpart
- [`file-upload-and-webshell-extension-and-mime-bypass`](../file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `file-upload-and-webshell` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-434, T1505`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 59 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (32), hackerone_disclosed_reports (11), CYBER_CPT/nuclei_templates (8), CYBER_CPT/sigmahq (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 13 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
