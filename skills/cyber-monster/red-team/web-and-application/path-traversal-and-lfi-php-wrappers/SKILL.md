---
name: path-traversal-and-lfi-php-wrappers
description: PHP stream wrapper exploitation. Covers php://filter chains for source disclosure, data and expect wrappers for execution, phar deserialization, and zip wrapper traversal. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["php wrapper", "php filter", "php data wrapper", "phar deserialization", "php expect"]
cwe: [CWE-22, CWE-98]
owasp: [A01:2021, A03:2021]
attack: [T1005]
capec: [CAPEC-126]
related: [path-traversal-and-lfi, path-traversal-and-lfi-encoding-bypass, path-traversal-and-lfi-lfi-to-rce, path-traversal-and-lfi-log-and-cache-poisoning]
parent: path-traversal-and-lfi
---

# Path Traversal and LFI Php Wrappers - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)

## Mechanism and Preconditions

PHP stream wrappers let an include or file function treat a scheme-prefixed string as a data source, so the security decision moves from the filesystem to PHP's wrapper layer. The php://filter wrapper chains base64, iconv, and dechunk conversions to disclose source or, with crafted conversion chains, to materialize bytes; data:// and expect:// embed the payload or a command directly; phar:// triggers unserialization of a crafted archive's metadata whenever any file operation touches the path; zip:// reaches an entry by fragment. The preconditions are a wrapper-accepting sink and the relevant wrappers being enabled, so the attacker converts a path parameter into source disclosure, object injection, or execution depending on which wrapper the sink honors.

- **Precondition chain:** a request-controlled string reaches a PHP file or include function, the relevant stream wrapper is enabled (filter always, data and expect and phar as configured), the sink does not canonicalize or reject scheme prefixes, and the wrapper's output is interpreted or unserialized rather than returned as opaque bytes.
- **Readable differential:** request a resource by plain path versus the same resource behind a php://filter chain; the wrapper is live when the response is the transformed form such as base64, and it reverts to plain-path behaviour once scheme prefixes are rejected.
- **Empirical grounding:** This maps to CWE-98 and CWE-22 under OWASP Top 10:2025 A01 Broken Access Control; SOURCES.md carries no php-wrapper-specific advisory, so grounding stays at the CWE and OWASP class and phar chains route to the deserialization skill rather than citing an invented CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to accept a scheme-prefixed path **THEN** start at parent class [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) (1 hop) to confirm the sink is a PHP file or include function
2. **IF** the sink returns transformed output for a php://filter prefix **THEN** use a base64-encode filter for non-destructive source disclosure before testing any conversion chain
3. **IF** a conversion chain of iconv or dechunk filters alters the output **THEN** treat the filter chain as a reachability signal and stop before materializing executable bytes
4. **IF** the parameter accepts data:// and allow_url_include is on **THEN** confirm the data wrapper is honored with an inert base64 body rather than any command payload
5. **IF** a file operation touches a phar:// path **THEN** switch to [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) (1 hop) because the primitive is unserialize, not inclusion
6. **IF** the sink resolves a zip:// entry by fragment **THEN** switch to [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md) (1 hop) for the archive traversal invariant
7. **IF** allow_url_include and the expect extension are disabled in php.ini **THEN** scope testing to the filter wrapper only, since data and expect execution are unavailable
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)
9. **IF** the path is confined to a basename inside a fixed directory and scheme prefixes are rejected **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A phar:// path triggers object unserialization of archive metadata | [`insecure-deserialization-php-gadgets`](../insecure-deserialization-php-gadgets/SKILL.md) | Impact flows through a PHP gadget chain, a different invariant than file interpretation |
| A zip:// fragment reaches an entry inside an uploaded archive | [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md) | The control to fix is archive extraction safety, not the stream wrapper allowlist |
| A data:// body with allow_url_include reaches an evaluation sink | [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) | Execution comes from dynamic evaluation of embedded code, a distinct invariant |
| Need parent class methodology | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Locate the PHP file or include function and confirm it accepts a scheme-prefixed string rather than a plain path.
2. Probe which wrappers are enabled with a non-destructive php://filter base64 disclosure of a known file, so capability is mapped before escalation.
3. Classify the primitive: a filter chain (read and conversion), data:// or expect:// (embedded execution), phar:// (unserialize), or zip:// (archive traversal).
4. Choose the branch from evidence: transformed output confirms the filter wrapper; an accepted data:// body confirms allow_url_include; a __wakeup or __destruct side effect on a phar:// path confirms the unserialize sink.
5. Define the baseline-versus-probe differential: request the resource by plain path, then behind the wrapper; only a wrapper-specific transformation or side effect counts.
6. Escalate one wrapper capability at a time and stop at the first that proves the invariant is missing, since deeper wrappers change impact, not the finding.
7. **Stop condition.** Stop when (a) a wrapper transforms or acts on the resource in a way a plain path cannot and reverts when scheme prefixes are rejected, (b) every scheme prefix is refused, or (c) proceeding would require executing a real command or materializing a shell; (a) is confirmation, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is the sink line plus a wrapper probe whose transformed output or inert side effect appears only with the scheme prefix and disappears once the input is confined to a realpath-checked basename, with no command run. Close with disabling URL and phar wrappers and mapping to fixed paths, then re-run the base64 probe to confirm rejection.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| php://filter/convert.base64-encode returning base64 of a known file | Proves read of source through the filter wrapper on any PHP build regardless of allow_url_include |
| A convert.iconv or dechunk chain changing the response payload | Proves the filter chain is reachable and composable, the precondition for materializing bytes |
| data:// body accepted and reflected | Proves allow_url_include is enabled, which upgrades the sink from read to embedded content |
| expect:// scheme recognized by the sink | Proves the expect extension is loaded, a direct command primitive on misconfigured hosts |
| phar:// path triggering a __wakeup or __destruct side effect | Proves an unserialize sink reachable through a file operation, routing to a gadget chain |
| zip:// fragment resolving an entry inside an uploaded archive | Proves archive traversal through the wrapper, distinct from filesystem traversal |

## Worked Contrast

**Vulnerable pattern:**

```php
<?php
// Wrapper-accepting sink: php://filter, data://, and phar:// all resolve here.
$doc = $_GET['doc'];
echo file_get_contents($doc);  // scheme prefix is honoured by the stream layer
```

**Hardened pattern:**

```php
<?php
// Only basenames inside a fixed directory; scheme prefixes can never resolve.
$DOCS = '/var/www/app/docs/';
$name = basename($_GET['doc'] ?? '');
$path = realpath($DOCS . $name);
if ($path === false || strncmp($path, $DOCS, strlen($DOCS)) !== 0) {
    http_response_code(404);
    exit('not found');
}
echo file_get_contents($path);  // realpath-confined; url/phar wrappers disabled in php.ini
```

**Why this matters:** The defect passes a raw request value to a stream function, so php://filter, data://, and phar:// prefixes are honoured by PHP's wrapper layer. The fix reduces the input to a basename, resolves it with realpath, and verifies containment inside a fixed directory, so no scheme prefix survives, while allow_url_include and phar stay disabled as defence in depth.

## When It Is NOT This Issue

- **Filter disclosure of a non-sensitive file:** base64 of a public template proves the wrapper works but carries no confidentiality impact on its own.
- **Wrappers disabled in php.ini:** with allow_url_include off and phar read disabled, data and phar branches are closed even if the parameter is attacker-controlled.
- **Basename-confined path:** a value reduced to basename and realpath-checked cannot carry a scheme prefix to the stream layer.
- **data:// rejected:** a sink that refuses the data scheme is not an embedded-content primitive regardless of filter behaviour.
- **phar path never touched:** a phar:// string that no file operation ever opens does not trigger unserialization.
- **Opaque download, not interpreted:** output streamed as an attachment that is never included or unserialized is a read, not execution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `path-traversal-and-lfi-php-wrappers` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `path-traversal-and-lfi-php-wrappers` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: path-traversal-and-lfi-php-wrappers
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
- [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `path-traversal-and-lfi-php-wrappers` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-22, CWE-98, T1005`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (5), CYBER_CPT/govuln (2), CYBER_CPT/hacker_recipes (2), CYBER_CPT/ctftime (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
