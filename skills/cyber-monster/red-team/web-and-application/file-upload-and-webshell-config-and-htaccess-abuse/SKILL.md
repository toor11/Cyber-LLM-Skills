---
name: file-upload-and-webshell-config-and-htaccess-abuse
description: Upload configuration file abuse. Covers uploading .htaccess, web.config, .user.ini and index.php overrides to enable execution, redirect handlers, or SSI processing. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["htaccess upload", "web.config upload", "user.ini upload", "upload config"]
cwe: [CWE-434]
owasp: [A04:2021]
attack: [T1505]
capec: [CAPEC-1]
related: [file-upload-and-webshell, file-upload-and-webshell-extension-and-mime-bypass, file-upload-and-webshell-polyglot-and-archive, file-upload-and-webshell-filename-and-path-abuse]
parent: file-upload-and-webshell
---

# File Upload and Webshell Config and Htaccess Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)

## Mechanism and Preconditions

This variant does not smuggle a script past a validator; it uploads a configuration file that rewrites how the web server treats the directory it lands in, so files the server would otherwise serve as inert data become executable or reinterpreted. On Apache a planted `.htaccess` can register a handler or an `AddType` mapping, on IIS a `web.config` can register a handler or enable server-side includes, and on PHP-FPM a `.user.ini` can set `auto_prepend_file`. The security decision is whether the upload directory honours directory-level configuration overrides at all. The attacker lands the configuration file first, then uploads otherwise-benign content that the new directive causes to execute. Confirmation is that a file inert before the configuration upload is evaluated after it, with no change to the content file itself.

- **Precondition chain:** the upload directory accepts a configuration file (`.htaccess`, `web.config`, `.user.ini`, or an overriding `index.php`), the web server honours directory-level overrides there (`AllowOverride`, FPM user-ini scanning, or `web.config` inheritance), the directory executes the handler the configuration enables, and a separately uploaded content file is reachable by URL.
- **Readable differential:** fetching the same benign content file before versus after the configuration file is present; a finding exists when the identical file is served verbatim before and evaluated after, and it closes when directory overrides are disabled so the configuration upload has no effect.
- **Empirical grounding:** CWE-434 under the file-upload taxonomy. SOURCES.md has no 2025 CVE specific to directory-override configuration uploads; the control is the server's `AllowOverride`, FPM `user_ini` scanning, or `web.config` inheritance policy rather than an application patch, so this variant stays grounded at the CWE-434 configuration-override level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a directory-override configuration upload **THEN** start at parent class [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) first (1 hop)
2. **IF** the server is Apache and the directory honours `.htaccess` overrides **THEN** test an `AddType` or `AddHandler` directive before uploading any content file
3. **IF** the server is IIS and a `web.config` is accepted in the upload path **THEN** test a handler or BuildProvider registration scoped to that directory
4. **IF** the stack is PHP-FPM and `.user.ini` is scanned in the upload directory **THEN** test an `auto_prepend_file` include pointing at an uploaded data file
5. **IF** the configuration enables server-side includes rather than a script handler **THEN** route the SSI directive-evaluation angle to [`server-side-includes-injection`](../server-side-includes-injection/SKILL.md)
6. **IF** the platform resolves configuration through the framework rather than the web server **THEN** confirm the stack with [`cms-and-framework-exploitation-php-and-laravel`](../cms-and-framework-exploitation-php-and-laravel/SKILL.md) before claiming override reach
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md)
8. **IF** the upload directory ignores directory-level overrides and the planted configuration changes nothing **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The planted configuration enables SSI directive processing | [`server-side-includes-injection`](../server-side-includes-injection/SKILL.md) | Invariant is template directive evaluation, not directory handler mapping |
| The override is resolved by the application framework, not the web server | [`cms-and-framework-exploitation-php-and-laravel`](../cms-and-framework-exploitation-php-and-laravel/SKILL.md) | Invariant is framework configuration precedence on PHP or Laravel |
| The server technology is unconfirmed before choosing a configuration file | [`web-fingerprinting-and-tech-detection`](../web-fingerprinting-and-tech-detection/SKILL.md) | Invariant is stack identification: Apache, IIS, or FPM decide which file matters |
| Need parent class methodology | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the server technology and its override model.** Determine whether the upload directory is served by Apache with `AllowOverride`, IIS reading `web.config`, or PHP-FPM scanning `.user.ini`, because each honours a different configuration file. The wrong file for the stack is inert.
2. **Verify the upload directory accepts a configuration filename.** Check whether the validator rejects `.htaccess`, `web.config`, or `.user.ini` by name or treats them as ordinary uploads; the whole variant depends on the configuration file landing in the serving directory.
3. **Record a pre-configuration baseline.** Upload a plain data file, fetch it, and confirm the server returns its bytes verbatim with the expected static content type. This proves the directory does not yet execute it.
4. **Plant the directory-override configuration file.** Upload a minimal configuration that maps a chosen extension to a handler or sets an include, scoped to that directory only, and confirm it is stored alongside the content.
5. **Re-fetch the unchanged content file.** Request the identical data file uploaded earlier and compare the response. The only variable changed is the presence of the configuration file, not the content.
6. **Stop condition.** Stop when the re-fetch either (a) now returns evaluated output for a content file previously served verbatim, confirming the override took effect, (b) is unchanged because overrides are disabled or the configuration filename was rejected, or (c) would require the handler to run a functional shell to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the before-and-after divergence on one unchanged content file attributable solely to the planted configuration, tied to the directory and the directive that enabled execution. The configuration upload succeeding by itself is not proof; the directive must change how the content file is served.
8. **Isolate the override layer that honoured it.** Name whether Apache `AllowOverride`, FPM user-ini scanning, or `web.config` inheritance made the directive live, so the fix targets the right layer.
9. **Close with the structural fix and verify.** Disable directory-level overrides in upload paths (`AllowOverride None`, FPM `user_ini.filename` cleared or the path excluded, `web.config` inheritance removed), reject configuration filenames at the validator, store uploads outside any served directory, then re-run the before-and-after fetch to confirm no divergence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An uploaded `.htaccess` accepted into an Apache-served directory | Proves the directory may honour `AddType` or `AddHandler` overrides on Apache |
| A `web.config` stored in an IIS upload path | Proves a handler or SSI registration can be scoped to that directory on IIS |
| A `.user.ini` with `auto_prepend_file` landing in a PHP-FPM directory | Proves per-directory PHP configuration is scanned where uploads land |
| A content file served verbatim before the configuration and evaluated after | Proves the override changed the directory's handling, the core confirmation for this variant |
| `AllowOverride None` on the upload directory | Proves Apache ignores planted `.htaccess` files, closing the override surface |
| Configuration filenames rejected by the upload validator by name | Proves the configuration file cannot land, so no directive can take effect |
| An `index.php` override shadowing the directory's default handler | Proves a planted entry point can intercept requests to that directory |

## Worked Contrast

**Vulnerable pattern:**

```apache
# Uploads land in a directory that honours per-directory overrides
<Directory /var/www/html/uploads>
    AllowOverride All        # a planted .htaccess here can add handlers
    Require all granted
</Directory>
# An uploaded .htaccess can then contain:  AddType application/x-httpd-php .img
```

**Hardened pattern:**

```apache
# Uploads cannot override server configuration and are never interpreted
<Directory /var/www/html/uploads>
    AllowOverride None       # planted .htaccess files are ignored
    php_admin_flag engine off
    SetHandler none
    Require all granted
</Directory>
# The validator also rejects filenames: .htaccess, .user.ini, web.config
```

**Why this matters:** The defective directory sets `AllowOverride All`, so an uploaded `.htaccess` can register a handler that executes otherwise-inert uploads; the hardened directory sets `AllowOverride None`, turns the PHP engine off, and clears the handler, so a planted configuration file has no effect and the stored content is always served as static bytes.

## When It Is NOT This Issue

- **Overrides disabled:** a directory with `AllowOverride None` or no `web.config` inheritance ignores any planted configuration file.
- **Configuration filename rejected:** a validator that refuses `.htaccess`, `.user.ini`, and `web.config` by name prevents the directive from ever landing.
- **Wrong server for the file:** an uploaded `.htaccess` under IIS, or a `web.config` under Apache, is inert because that server does not read it.
- **Non-served storage:** uploads written outside any document root are never subject to directory-level handler configuration.
- **Override present but directory not executable:** a honoured `.htaccess` that cannot enable an installed interpreter changes nothing executable.
- **Scanning path points elsewhere:** an FPM `user_ini.filename` directed away from the upload directory means a `.user.ini` there is not scanned.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `file-upload-and-webshell-config-and-htaccess-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `file-upload-and-webshell-config-and-htaccess-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: file-upload-and-webshell-config-and-htaccess-abuse
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
- [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) - Web and Application (leaf)
- [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `file-upload-and-webshell-config-and-htaccess-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-434, T1505`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/github_security_md (4), CYBER_CPT/oxdf (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
