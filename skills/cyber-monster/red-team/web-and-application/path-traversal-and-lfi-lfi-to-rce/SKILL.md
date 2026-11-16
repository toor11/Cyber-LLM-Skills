---
name: path-traversal-and-lfi-lfi-to-rce
description: LFI to remote code execution chains. Covers escalating file inclusion to execution through log poisoning, session file injection, /proc/self/environ, upload plus include, and pearcmd or ssh authorized_keys writes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["lfi to rce", "log poisoning", "lfi rce", "inclusion to code execution"]
cwe: [CWE-22, CWE-98]
owasp: [A01:2021, A03:2021]
attack: [T1005]
capec: [CAPEC-126]
related: [path-traversal-and-lfi, path-traversal-and-lfi-encoding-bypass, path-traversal-and-lfi-php-wrappers, path-traversal-and-lfi-log-and-cache-poisoning]
parent: path-traversal-and-lfi
---

# Path Traversal and LFI LFI to RCE - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)

## Mechanism and Preconditions

A local file inclusion reaches a dynamic include or require whose resolved path is influenced by request input; on its own it only discloses source, so escalation to execution requires landing attacker-controlled bytes on a path the include will then interpret. The usual write channels are a poisoned Apache or Nginx access or error log (via a crafted User-Agent or Referer), a PHP session file under /var/lib/php/sessions keyed by the PHPSESSID cookie, /proc/self/environ, a mail spool, an uploaded file, or pearcmd.php driven through the include. The security decision is at the include call and whether the resolved path is confined to a server-side allowlist. When it is not, the planted content is parsed as code in the web runtime and the attacker gains arbitrary execution as the web user.

- **Precondition chain:** a dynamic include or require resolves a request-influenced path with no canonical allowlist, wrapper and null-byte handling leave that path reachable, a file whose contents the attacker controls lands on an includable path, and the included bytes are interpreted rather than returned as text.
- **Readable differential:** include a known-benign server file versus the poisoned log, session, or environ path; execution is proven when an inert marker the attacker planted is evaluated and its output appears, and the include reverts to inert text once the path is pinned to an allowlist.
- **Empirical grounding:** CWE-98 and CWE-22 sit under OWASP Top 10:2025 A01 Broken Access Control; FortiWeb CVE-2025-64446 shows a relative path traversal chained into operating-system command execution with CVE-2025-58034, the same traversal-to-execution escalation shape this skill covers.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to be a dynamic include sink **THEN** start at parent class [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) (1 hop) to classify the read primitive before attempting any execution
2. **IF** the include reads Apache or Nginx access and error logs that record a request-controlled User-Agent or Referer **THEN** treat access.log, error.log, and the mail spool as three separate writable-then-includable sinks and plant an inert marker in each
3. **IF** the runtime writes PHP session files to /var/lib/php/sessions keyed by the PHPSESSID cookie **THEN** set an inert marker in a session variable, then include the session file by its PHPSESSID path
4. **IF** only /proc/self/environ or /proc/self/fd descriptors are readable and the SAPI exposes request headers there **THEN** use the environ pseudo-file as the writable-then-included surface
5. **IF** the path honors php:// or data:// wrappers rather than a filesystem log **THEN** switch to [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) (1 hop) because the execution primitive is a wrapper, not a poisoned file
6. **IF** the chain depends on first uploading a file whose bytes are later included **THEN** switch to [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) (1 hop) to control the stored path and extension
7. **IF** filters strip ../ or a null byte truncates the appended suffix differently across layers **THEN** switch to [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) (1 hop)
8. **IF** the writable sink is specifically a log file and you need rotation and format constraints **THEN** switch to [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this chain **THEN** pivot to the paired Blue skill [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)
10. **IF** the include is confined to a server-side allowlist and no writable file lands on an includable path **THEN** STOP and record a verified non-finding rather than forcing an execution story

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Path reaches a php:// or phar:// wrapper instead of a poisoned file | [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) | Execution comes from wrapper evaluation or phar unserialize, a different primitive than log poisoning |
| Chain requires an uploaded artefact to be stored then included | [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) | The control to fix is upload storage and extension handling, not the include allowlist alone |
| Phar include triggers object deserialization of archive metadata | [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) | Impact flows through a PHP gadget chain, not plain file interpretation |
| Need parent class methodology | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Locate the dynamic include or require and classify the read primitive: full path control, prefix-fixed with suffix control, or extension-appended, and note whether include, require, include_once, or a framework template loader resolves it.
2. Confirm pure-read reachability first with a known server file outside the web root, so disclosure is separated from execution before anything is planted.
3. Enumerate writable-then-includable sinks in priority order: access.log and error.log, the PHPSESSID session file, /proc/self/environ, the mail spool, an uploaded path, and pick the one whose write channel you already control.
4. Choose the branch from evidence: if the include echoes file bytes you have read and can test interpretation; if the response length tracks a named file's size the include is reaching the filesystem; if a wrapper prefix changes behaviour the primitive is a wrapper, not a log.
5. Define the baseline-versus-probe differential: request the sink path with an inert non-executing marker written to it, then with the same marker wrapped so the interpreter would evaluate it; only an evaluated-output difference distinguishes execution from source disclosure.
6. **Stop condition.** Halt when (a) the planted inert marker is evaluated and its output appears, proving interpretation, (b) the marker is returned verbatim as text across every sink, proving read-only disclosure, or (c) advancing would require writing a real web shell or persistent file; (a) is remote code execution, (b) is an inclusion read finding and not execution, (c) is out of scope.
7. **State what counts as proof.** Proof is the exact include line plus one poisoned sink where a benign planted expression evaluates in the web runtime and stops evaluating once the path is confined, with no destructive payload written. A readable log containing your User-Agent is not proof until the include interprets it.
8. Close with the structural fix: replace the resolved path with a closed map from caller token to a fixed file set, disable URL and wrapper inclusion, confine includable directories, and re-run the inert-marker probe against the patched build to confirm it returns as text.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| include or require whose argument concatenates a request parameter | Proves full or partial path control into the PHP include resolver, the precondition for turning a read into execution on any PHP SAPI |
| Reflected User-Agent or Referer appearing verbatim in a readable access.log | Proves the log is a writable-then-includable sink on Apache or Nginx, though interpretation is still unproven |
| PHPSESSID-named file under /var/lib/php/sessions carrying attacker-set session values | Proves the session store is a controllable write surface keyed by the cookie on PHP-FPM or mod_php |
| /proc/self/environ reflecting request headers to the web process | Proves an environ-based write channel on Linux SAPIs where the log path is not includable |
| Response length that scales with the size of a named server file | Proves the include reaches the filesystem rather than a template cache, usable as a low-noise read oracle |
| pearcmd.php reachable via include with argv-style query parameters | Proves a local PEAR binary can be driven through the include, a classic read-to-write escalation on default PHP images |
| Null byte or path truncation changing the appended extension | Proves the suffix guard differs across the parser and the filesystem, extending which sinks become includable |

## Worked Contrast

**Vulnerable pattern:**

```php
<?php
// Request-controlled view name reaches include with no confinement.
// A poisoned access.log or PHP session file on this path is interpreted as PHP.
$view = $_GET['view'];
include '/var/www/app/views/' . $view;  // ../../var/log/apache2/access.log reaches here
```

**Hardened pattern:**

```php
<?php
// Closed map from caller token to a fixed view file; nothing else is includable.
$VIEWS = [
    'home'    => '/var/www/app/views/home.php',
    'profile' => '/var/www/app/views/profile.php',
];
$key = $_GET['view'] ?? 'home';
if (!isset($VIEWS[$key])) {
    http_response_code(400);
    exit('unknown view');
}
include $VIEWS[$key];  // path never derived from attacker bytes; allow_url_include off
```

**Why this matters:** The defect assembles the include path from request input, so any file the attacker can write to (logs, session files, environ) becomes executable code. The fix removes path derivation entirely: the caller selects a key, the server resolves it to a fixed file, and URL and wrapper inclusion stay disabled, so no poisoned sink is reachable.

## When It Is NOT This Issue

- **Read-only disclosure mislabelled as execution:** the include returns the log or a system file as text but never evaluates a planted marker. That is an inclusion read finding, not code execution.
- **Allowlisted include:** the view name is resolved through a server-side map and unknown keys are rejected, so a traversal string that reaches the parameter never reaches the filesystem.
- **Non-PHP include target:** a Node or Python app that reads a file and returns it does not interpret it; with no interpreter on the include path there is no execution.
- **Writable log that is never included:** a poisonable access.log only matters if a dynamic include can resolve its path; confirm the include reaches it before claiming a chain.
- **open_basedir or container confinement:** a runtime that pins includable paths to the app directory blocks the log and session sinks even when the parameter is attacker-controlled.
- **Session files the attacker cannot predict:** if session storage uses a database or a random path, the session-poisoning branch is closed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `path-traversal-and-lfi-lfi-to-rce` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `path-traversal-and-lfi-lfi-to-rce` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: path-traversal-and-lfi-lfi-to-rce
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-22, CWE-98 | Mapping: T1005]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)
- [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `path-traversal-and-lfi-lfi-to-rce` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-22, CWE-98, T1005`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (8), CYBER_CPT/L5/ctf_search (4), CYBER_CPT/ctf_search (3), CYBER_CPT/hacktricks (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
