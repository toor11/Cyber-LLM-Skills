---
name: path-traversal-and-lfi
description: Exploits path traversal and local file inclusion with encoding and normalization bypasses, PHP wrappers, log poisoning, and LFI-to-RCE chains. Use when a parameter names a file, template, language pack, image, or download path.
family: web-and-application
tier: core
triggers: ["path traversal", "lfi", "local file inclusion", "directory traversal", "file read", "dotdot slash", "php wrapper"]
cwe: [CWE-22, CWE-98]
owasp: [A01:2021, A03:2021]
attack: [T1005]
capec: [CAPEC-126]
related: [path-traversal-and-lfi-encoding-bypass, path-traversal-and-lfi-php-wrappers, path-traversal-and-lfi-lfi-to-rce, sql-injection]
---

# Path Traversal and LFI - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)

## Mechanism and Preconditions

A request parameter that names a file, template, language pack, image, or download path is joined to a server-side base directory and passed to a filesystem open or include without confirming the resolved path stays inside the intended root. Because path APIs resolve parent segments, drive letters, UNC prefixes, and symlinks, the string the validator inspected and the path the operating system opens can diverge, letting the read escape the base. The decision point is canonicalisation: whether the application resolves the final real path and checks containment before opening. The attacker gains disclosure of files the web process can read, and on PHP include sinks can reach code execution through wrappers or poisoned logs. Confirmation is a differential between a known in-root file and a guaranteed-missing one, versus an out-of-root target that returns content.

- **Precondition chain:** A request value reaches a filesystem path or include, the application joins it to a base without resolving the real path, and no containment check confirms the resolved path stays under the intended root.
- **Readable differential:** A known in-root file versus a guaranteed-missing one establishes the read channel, then an out-of-root target is compared; a finding exists when the out-of-root target returns content, and it stops once the real path is resolved and confined to the root.
- **Empirical grounding:** CWE-22 Path Traversal and CWE-98 for PHP include under OWASP Top 10:2025 A01 Broken Access Control; CVE-2025-12097 (relative traversal), CVE-2025-32103 (CrushFTP UNC and network path), and GHSA-rmw8-5j53-j987 (Erlang/OTP inets httpd directory traversal) are 2025 instances across distinct resolution bugs.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves encoded or normalization-based evasion **THEN** switch to [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) (1 hop)
2. **IF** the sink is a PHP include reachable through stream wrappers **THEN** switch to [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) (1 hop)
3. **IF** a confirmed read can be turned into code execution **THEN** switch to [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) (1 hop)
4. **IF** the chain involves poisoning a log or cache then including it **THEN** switch to [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) (1 hop)
5. **IF** the value resolves a UNC or network path on Windows **THEN** test `\\host\share` forms because network resolution escapes the local root differently
6. **IF** the parameter names an upload destination that is written, not read **THEN** route to [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md)
7. **IF** a scheme such as file:// reaches a server-side fetcher rather than open() **THEN** route to [`ssrf`](../ssrf/SKILL.md) because the read happens through the fetch client
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)
9. **IF** the resolved real path is confined to the root and no out-of-root target returns **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The parameter names an upload destination that is written, not read | [`file-upload-and-webshell-filename-and-path-abuse`](../file-upload-and-webshell-filename-and-path-abuse/SKILL.md) | The sink is a write path, enabling placement rather than disclosure |
| Traversal occurs during archive extraction | [`zip-slip-and-archive-extraction-attacks`](../zip-slip-and-archive-extraction-attacks/SKILL.md) | The decompressor writes outside the target directory, a different stage |
| A URL scheme such as file:// reaches a server-side fetcher | [`ssrf`](../ssrf/SKILL.md) | The read happens through the fetch client, not a filesystem path |
| Target matches `path-traversal-and-lfi-encoding-bypass` | [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `path-traversal-and-lfi-php-wrappers` | [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `path-traversal-and-lfi-lfi-to-rce` | [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `path-traversal-and-lfi-log-and-cache-poisoning` | [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the path parameter and sink.** Determine whether the value is a full filename, a fragment joined to a base, or a key into a map, and whether the sink is open/read, an include, or a download helper. The sink type decides the escalation route.
2. **Confirm a read channel with an in-root pair.** Request a file known to exist in the root and a guaranteed-missing sibling and compare responses, so later out-of-root results are interpretable against a real baseline.
3. **Choose the traversal form from the platform.** Decide between relative `../` ladders, absolute paths, Windows backslash, and UNC `\\host\share` forms based on the observed OS and framework, rather than firing all forms blindly.
4. **Apply the out-of-root differential.** Request a benign out-of-root file (for example a world-readable system file) and compare against the missing-file baseline; content that only the out-of-root target returns indicates escape.
5. **Separate read from execution.** Confirm plain disclosure before considering wrappers, log poisoning, or UNC, because each of those is a distinct downstream skill with its own invariant.
6. **Stop condition.** Halt when a probe either (a) returns out-of-root content that disappears once the real path is confined to the root, (b) returns the missing-file response for every out-of-root form, or (c) would require reading genuinely sensitive secrets to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an out-of-root path returning file content distinct from the missing-file baseline, tied to one changed parameter, plus the source line that opens the joined path without a resolved containment check. A 500 or a generic not-found is not proof.
8. **Close with the structural fix and verify it.** Map the request value to an identifier that selects a server-side filename, or resolve the real path and reject anything not under the canonical root, and re-run the in-root, missing, and out-of-root triple to confirm only in-root reads succeed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A request value joined to a base directory and passed straight to open() | Proves an unconfined filesystem path on any stack that trusts the joined string over the resolved real path |
| An out-of-root file returning content distinct from the missing-file baseline | Proves the read escaped the intended root, the core CWE-22 confirmation |
| A Windows `\\host\share` value resolving to a network path | Proves UNC resolution escapes the local root, a distinct Windows path-handling bug |
| A PHP include whose filename is request-derived | Proves a CWE-98 include sink that can reach wrappers or poisoned logs for execution |
| A download helper that honours parent segments in the name | Proves the helper resolves traversal rather than treating the name as a leaf |
| An absolute path override replacing the base entirely | Proves the join is defeated when the value starts at the filesystem root |

## Worked Contrast

**Vulnerable Pattern (express - path traversal):**

```javascript
}

  // Vulnerable: path.join resolves attacker-supplied parent segments.
  const target = path.join(reportsDir, file);
  res.download(target, path.basename(target), (error) => {
    if (error && !res.headersSent) {
      res.status(404).json({ error: 'File not found' });
    }
  });
});

app.listen(Number(process.env.PORT || 3000));
```

**Fixed / Hardened Pattern (express - path traversal):**

```javascript
}

  const report = reports.get(name);
  if (!report) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  res.attachment(report.downloadName);
  res.type('application/octet-stream');
  return res.send(report.bytes);
});

app.use((error, req, res, next) => {
  console.error('internal_error');
```

**Why this matters:** An unauthenticated traversal can disclose files readable by the web process outside the public report directory.

## When It Is NOT This Issue

- **Identifier-to-filename map:** the parameter selects a server-side filename through a closed map, so the caller never supplies a path at all.
- **Resolved containment check:** the code resolves the real path and rejects anything not under the canonical root, so parent segments and symlinks cannot escape.
- **Missing-file response for every out-of-root form:** when out-of-root targets return the same not-found as a missing sibling, no read channel exists.
- **Write sink, not read:** a parameter that names where a file is written is an upload-path finding with a different invariant, not disclosure.
- **Chroot or container confinement:** a jailed filesystem means even a traversal string cannot reach sensitive files outside the root.
- **Error masking mistaken for a read:** a verbose stack trace that echoes the attempted path is not file content and is not CWE-22 proof.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `path-traversal-and-lfi` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `path-traversal-and-lfi` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: path-traversal-and-lfi
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-22, CWE-98 | Mapping: T1005]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `path-traversal-and-lfi` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-22, CWE-98, T1005`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 74 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (32), securecode-web (20), CYBER_CPT/nuclei_templates (12), SecEval/cwe (7) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
