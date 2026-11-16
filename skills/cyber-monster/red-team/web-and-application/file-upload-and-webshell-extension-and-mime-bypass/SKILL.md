---
name: file-upload-and-webshell-extension-and-mime-bypass
description: Upload extension and MIME validation bypass. Covers double extensions, alternate executable extensions, case and trailing-character tricks, null bytes, content-type spoofing and magic-byte prefixes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["upload extension bypass", "mime bypass", "content type bypass", "double extension"]
cwe: [CWE-434]
owasp: [A04:2021]
attack: [T1505]
capec: [CAPEC-1]
related: [file-upload-and-webshell, file-upload-and-webshell-config-and-htaccess-abuse, file-upload-and-webshell-polyglot-and-archive, file-upload-and-webshell-filename-and-path-abuse]
parent: file-upload-and-webshell
---

# File Upload and Webshell Extension and Mime Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)

## Mechanism and Preconditions

The validator and the runtime disagree about what type a file is. The upload gate decides acceptance from a declared signal such as the submitted extension, the client `Content-Type`, or a magic-byte prefix, while the web server decides execution from a different signal such as the final extension Apache maps to a handler or a double extension the parser splits differently. The attacker makes those two decisions diverge: a trailing or doubled extension, an alternate executable suffix like `.phtml` or `.phar`, case or trailing-character tricks, a spoofed `Content-Type`, or a valid magic-byte header in front of script text. The gain is that a file the validator classified as an image is handled by the interpreter as a program. Confirmation is that the accepted file is evaluated when fetched, proving the runtime read a different type than the validator believed.

- **Precondition chain:** the validator classifies the upload from a client-controlled or prefix signal, the web server maps the stored file to an interpreter by a different signal, the two classifications disagree for a craftable filename or header, and the stored file is reachable by URL.
- **Readable differential:** the same bytes submitted with a type the validator trusts versus with the final extension the runtime executes; a finding exists when the runtime evaluates what the validator accepted as an image, and it closes when acceptance is driven by sniffed content and the stored name carries a single safe extension.
- **Empirical grounding:** CWE-434. SOURCES.md anchors this with GHSA-hq96-gvmx-qrwp, where WeGIA accepted a file on MIME alone and was beaten by placing valid XLSX magic bytes in front of the payload, a documented bypass of the earlier CVE-2025-22133 fix; it is the canonical 2025 case of the validator believing a different type than the runtime.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a type-belief disagreement **THEN** start at parent class [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) first (1 hop)
2. **IF** the validator trusts the client `Content-Type` only **THEN** submit mismatched sniffed content versus declared type to confirm which signal it reads
3. **IF** the validator checks a magic-byte prefix **THEN** test a valid image header in front of script text to split the prefix from the final extension
4. **IF** acceptance survives but the directory will not execute the final extension **THEN** pivot to [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) to make the directory execute it
5. **IF** the bypass relies on case folding, trailing dots, or unicode-equivalent characters **THEN** route the normalisation angle to [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md)
6. **IF** acceptance depends on the stored name rather than the declared type **THEN** route to [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)
8. **IF** acceptance is driven by sniffed content and the stored file carries a single safe extension the runtime cannot execute **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The accepted file will not execute without a directory handler change | [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) | Invariant is directory execution configuration, not the type-belief disagreement |
| The bypass uses case, trailing, or unicode-equivalent characters | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | Invariant is string normalisation before the comparison |
| Acceptance turns on the stored filename rather than the declared type | [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) | Invariant is canonicalisation of the stored name, not type classification |
| Need parent class methodology | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find which signal the validator classifies on.** Read the handler to see whether acceptance is decided by the submitted extension, the client `Content-Type`, a magic-byte sniff, or re-encoding. Name that signal precisely, because the bypass must satisfy it while diverging from the runtime.
2. **Find which signal the runtime executes on.** Determine how the web server maps the stored file to an interpreter: the final extension Apache sees, a double-extension split, or a handler tied to `.phtml` or `.phar`. The disagreement between these two signals is the whole vulnerability.
3. **Record a clean-accept baseline.** Upload a genuinely matching file with correct magic bytes, extension, and declared type, fetch it, and confirm it is served verbatim as an image. This fixes the validator's accept condition.
4. **Craft one divergence at a time.** Change exactly one signal the runtime reads while keeping the validator's accept signal intact: add a doubled or trailing extension, swap to an alternate executable suffix, or prepend a valid image header to script text. Keep every other field at the baseline.
5. **Fetch the stored file and compare to the baseline.** Request the accepted file's URL and check whether the response is the stored bytes or evaluated output.
6. **Stop condition.** Stop when the fetch either (a) returns evaluated output for a file the validator accepted as an image, confirming the type disagreement is exploitable, (b) returns the stored bytes verbatim because the runtime mapped it to no interpreter, or (c) would require a functional shell to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single accepted file whose validator-believed type is an image yet whose fetched output shows runtime evaluation, with the exact signal that diverged named. A spoofed `Content-Type` the server still serves as static bytes is not proof.
8. **Separate the validator fix from the execution fix.** Note whether closing the type disagreement alone suffices or whether the directory would still execute the final extension, which belongs to the configuration sibling.
9. **Close with the structural fix and verify.** Decide acceptance by server-side content sniffing, re-encode images, store under a server-generated single-extension name, and serve from a non-interpreting location, then re-run the crafted uploads to confirm they are returned verbatim.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A double extension such as a script suffix followed by an image suffix | Proves the validator and the server split the filename at different points on Apache |
| An alternate executable suffix like `.phtml` or `.phar` accepted as media | Proves the handler map reaches extensions the validator did not denylist |
| A valid magic-byte image header prepended to script text | Proves content-sniffing acceptance can carry an executable tail, as in the WeGIA magic-prefix case |
| A spoofed client `Content-Type` driving acceptance | Proves the validator trusts a client-declared type rather than sniffed content |
| Case or trailing-character variants of a blocked extension | Proves the extension comparison is not normalised before matching |
| Server-side re-encoding that rewrites the image on accept | Proves a control that strips the executable tail and defeats the prefix trick |
| A stored single-extension server-generated name | Proves the runtime cannot be steered to an interpreter by the submitted name |

## Worked Contrast

**Vulnerable pattern:**

```python
BLOCKED = {".php", ".phtml", ".phar"}

def accept_upload(filename, declared_type):
    # Denylist on extension plus trust in the client Content-Type
    ext = filename[filename.rfind("."):].lower()
    if ext in BLOCKED:
        raise ValueError("blocked extension")
    if not declared_type.startswith("image/"):
        raise ValueError("not an image")
    return store(filename)       # stored name keeps the client extension
```

**Hardened pattern:**

```python
import puremagic, uuid

ALLOWED = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif"}

def accept_upload(data):
    sniffed = puremagic.from_string(data, mime=True)   # type from content, not the client
    ext = ALLOWED.get(sniffed)
    if ext is None:
        raise ValueError("unsupported content")
    return store(uuid.uuid4().hex + ext, data)         # server-generated single extension
```

**Why this matters:** The defective validator denylists a few extensions and trusts the client `Content-Type`, so a doubled extension or spoofed type that the runtime still maps to an interpreter slips through; the fixed validator decides the type from sniffed content and rewrites the stored name to a single safe extension, so the runtime and the validator agree on one type.

## When It Is NOT This Issue

- **Content sniffing on accept:** a validator that classifies from server-side sniffed bytes cannot be fooled by a declared type or extension.
- **Re-encoded output:** an upload rewritten to a canonical image on accept loses any appended script, so the prefix trick dies.
- **Single-extension server naming:** a stored server-generated name with one safe extension gives the runtime nothing to map to an interpreter.
- **Non-executing store:** even an accepted script file served as static bytes from a non-interpreting path does not execute.
- **Denylist match is the control working:** a blocked `.phtml` that is rejected is the validator functioning, not evidence of a bypass.
- **MIME mismatch with no runtime handler:** a spoofed `image/png` stored and served as an image is a cosmetic mismatch, not execution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `file-upload-and-webshell-extension-and-mime-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `file-upload-and-webshell-extension-and-mime-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: file-upload-and-webshell-extension-and-mime-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-434 | Mapping: T1505]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) - Blue Detection/Defense Counterpart
- [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) - Web and Application (core)
- [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `file-upload-and-webshell-extension-and-mime-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-434, T1505`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/github_security_md (4), CYBER_CPT/sigmahq (3), bug-bounty-pentest-en (2), ctf-solver-dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
