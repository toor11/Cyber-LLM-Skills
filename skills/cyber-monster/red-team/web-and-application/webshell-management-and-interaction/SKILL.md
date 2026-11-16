---
name: webshell-management-and-interaction
description: "Operates and stabilizes an uploaded web shell: choosing the right interpreter, evading static detection, maintaining access, and pivoting through the web user context. Use after achieving file write or upload execution on a web server."
family: web-and-application
tier: leaf
triggers: ["webshell usage", "webshell interaction", "manage webshell", "shell stability web"]
cwe: [CWE-434]
owasp: []
attack: [T1505]
capec: [CAPEC-1]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Webshell Management and Interaction - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A web shell is a file an attacker placed inside the served tree that the server then hands to an interpreter, turning a static upload path into an execution context under the web user. The security decision is made by the server's handler mapping: if the upload directory is inside the document root and the extension (.php, .jsp, .aspx, .phar) is wired to FPM, a servlet container, or a handler, requesting the file runs it instead of downloading it. Management then means interacting with that context through a parameter, a base64-wrapped body, or a tool such as weevely, antsword, or behinder, and pivoting through the web account's reach. Proof for an assessment is a benign marker that demonstrates the interpreter executed, never a command-execution recipe, and the gain is scoped by what the web user can touch.

- **Precondition chain:** A file an attacker controls is written inside the document root, the server maps that file's extension to an interpreter for that directory, and the path is reachable so a request invokes execution rather than a plain download.
- **Readable differential:** The same uploaded marker file is requested as served bytes versus requested as an interpreted resource; a finding exists when the interpreted request returns the computed marker, and it reverts to returning verbatim bytes once the interpreter is disabled for that directory.
- **Empirical grounding:** SOURCES.md carries no advisory specific to post-upload web shell interaction, so this stays at taxonomy: CWE-434 unrestricted upload of a file with a dangerous type and the ATT&CK T1505 server software component technique, with the execution-context failure falling under OWASP Top 10:2025 A02 Security Misconfiguration.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the upload lands inside the document root and the extension maps to an interpreter **THEN** this is the primary case; prove the execution context with a single benign static marker
2. **IF** the server is PHP and .php, .phtml, or .phar are handler-mapped **THEN** probe which extensions FPM actually executes before assuming .php is the only one
3. **IF** the server is Java and the drop is a .jsp under a deployed context **THEN** check the servlet mapping for the uploaded path
4. **IF** the server is .NET and the drop is .aspx or .ashx **THEN** check handler registration for the upload directory
5. **IF** the uploaded file is returned verbatim as text **THEN** the interpreter is disabled for that path; record served-but-inert rather than execution
6. **IF** access must be stabilised through the web user **THEN** scope every action to the web account and avoid any destructive or data-changing command
7. **IF** reaching this point required defeating an upload filter **THEN** route the delivery vector to [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the uploaded marker is never interpreted on any reachable path **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The gap is the upload filter accepting the file | [`file-upload-and-webshell-extension-and-mime-bypass`](../file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) | Delivery via MIME or extension bypass is a different invariant than execution context |
| The drop rides a polyglot or archive member | [`file-upload-and-webshell-polyglot-and-archive`](../file-upload-and-webshell-polyglot-and-archive/SKILL.md) | Container-level smuggling differs from interpreter mapping |
| Execution is re-enabled by an uploaded .htaccess | [`file-upload-and-webshell-config-and-htaccess-abuse`](../file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) | A config override is a distinct control failure from the stored file itself |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the upload sink and its handler mapping.** Determine the exact directory the file is written to and whether the server's configuration maps that directory's extensions to an interpreter; this mapping, not the upload itself, is the decision point.
2. **Classify the stack and its executable extensions.** PHP-FPM, a servlet container, and an ASP.NET handler each run a different extension set, so enumerate which forms the server treats as code versus data.
3. **Record a served-bytes baseline.** Upload a plain text marker and request it; capturing it returned verbatim establishes what a non-executing path looks like.
4. **Probe the execution context with a benign marker.** Place a marker whose only effect, if interpreted, is to emit a fixed static string, then request it and compare against the served-bytes baseline. No command execution, no system calls.
5. **Confirm scope, not reach.** If the marker is interpreted, note that the context is the web user and stop at demonstrating execution; do not run commands that read, write, or delete real data.
6. **Stop condition.** Halt when the request either (a) returns the computed marker, proving interpretation, (b) returns the file verbatim, proving the interpreter is disabled, or (c) would require running an actual system command to go further. Case (a) is the finding, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is the uploaded marker file returning its interpreted output (a fixed static string the raw bytes could not produce) on a reachable path, plus the handler-mapping line that enables it; a file that merely uploaded successfully is not proof of execution.
8. **Close with the structural fix.** Store uploads outside the served tree, serve them inert with a forced download disposition, and disable the interpreter for any upload directory that must stay under the root. Verify by re-requesting the marker and seeing it return as bytes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An upload directory under the document root with .php mapped to FPM | Proves the stored-file path has an execution context on a PHP stack, the core web-shell precondition |
| A requested .phtml or .phar returning computed output | Proves the handler maps more than .php, so blocking a single extension does not remove execution |
| A .jsp under a deployed servlet context returning rendered output | Proves interpretation on a Java application server rather than static delivery |
| An uploaded file returned with its bytes verbatim and a download disposition | Proves the interpreter is disabled for that path, which is the inert, non-finding state |
| An .htaccess in the upload directory adding an AddHandler line | Proves a config override re-enabled execution that the base server denied |
| Antsword, behinder, or weevely User-Agent and encoder traffic to one path | Proves an interactive web-shell client is driving a single endpoint on the web tier |
| A base64-wrapped parameter whose decoded value is echoed back computed | Proves an interpreted request-to-response loop distinct from static file serving |

## Worked Contrast

**Vulnerable pattern:**

```nginx
# User uploads are written under the document root, and PHP-FPM is wired to
# run anything ending in .php in that directory, so a planted file executes.
location /uploads/ {
    root /var/www/html;                     # /var/www/html/uploads/shell.php is live
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php-fpm.sock;  # interpreter runs the upload
    }
}
```

**Hardened pattern:**

```nginx
# Uploads live outside the served tree and are returned inert; nothing in the
# upload path is ever handed to an interpreter.
location /uploads/ {
    alias /srv/upload-store/;                # outside the document root
    location ~ \.php$ { deny all; }          # no interpreter for uploaded files
    default_type application/octet-stream;    # served as bytes, never executed
    add_header Content-Disposition "attachment";
}
```

**Why this matters:** The defect is that the upload directory sits under the root and its extensions are mapped to an interpreter, so a stored file becomes code. The structural control relocates uploads outside the served tree, forces an inert download disposition, and denies the interpreter for that path, removing the execution context entirely.

## When It Is NOT This Issue

- **Uploaded file served verbatim:** if requesting the file returns its raw bytes with a download disposition, the interpreter is disabled and there is no execution context, only storage.
- **Upload outside the web root:** a file written to a path that the web server never serves cannot be invoked, so the dangerous-type upload has no reachable sink.
- **Extension blocked at the handler:** a server that maps only .php and strictly denies .phtml, .phar, and double extensions for that directory is enforcing the control, not exhibiting the bug.
- **Self-contained sandbox render:** an upload rendered only inside an isolated converter or thumbnailer with no shell reach is a processing feature, not an execution context.
- **Antivirus quarantine on write:** a file removed or neutralised before it is ever requested was never executable, so the toolchain traffic is not proof of a live shell.
- **Marker returns stored text, not computed output:** a marker that comes back as the literal bytes you uploaded shows storage, not interpretation, and must not be reported as code execution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `webshell-management-and-interaction` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `webshell-management-and-interaction` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: webshell-management-and-interaction
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-434 | Mapping: T1505]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `webshell-management-and-interaction` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-434, T1505`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (3), CYBER_CPT/github_security_md (2), CYBER_CPT/go_exploitdb (2), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
