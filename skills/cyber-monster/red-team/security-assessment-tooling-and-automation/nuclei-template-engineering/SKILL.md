---
name: nuclei-template-engineering
description: "Authors non-destructive Nuclei v3 YAML detection templates: HTTP/DNS/SSL/file protocol blocks, status/word/regex/DSL matchers, version extractors, request flow variables, and rate-safe validation. Use when writing custom Nuclei checks for version fingerprinting, misconfigurations, or exposure verification."
family: security-assessment-tooling-and-automation
tier: flagship
triggers: ["nuclei template", "write nuclei yaml", "nuclei matcher", "nuclei extractor", "nuclei v3 schema"]
cwe: [CWE-200]
owasp: [A05:2021]
attack: []
capec: []
related: [nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting, openapi-and-graphql-schema-auditor-scripting]
---


# Nuclei Template Engineering - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **flagship** | Paired Counterpart: [`waf-and-modsecurity-crs-rule-engineering`](../../../blue-team/security-automation-and-tool-development/waf-and-modsecurity-crs-rule-engineering/SKILL.md)

## Mechanism and Preconditions

Authoring Nuclei v3 templates that prove a condition without changing state: one or more `http:` requests, matchers combined with `matchers-condition: and`, and a `type: dsl` matcher or extractor for the part of the response that distinguishes a real match from a catch-all. The engineering problem is specificity — most false positives in a template corpus come from matching a status code or a common word alone.

- **`matchers-condition: and` is the default you want.** Nuclei defaults to OR across matchers, so two matchers without the condition report when either matches.
- **Extractors turn a match into evidence.** An extractor for the version string or the header value makes the finding reviewable without re-running the request.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the check targets a technology **THEN** require a technology-specific header or body marker *and* the vulnerable behaviour, never the status alone.
2. **IF** the response is a single-page app catch-all **THEN** add a DSL matcher excluding the app shell (`!contains(tolower(body), '<html')`) before publishing.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`waf-and-modsecurity-crs-rule-engineering`](../../../blue-team/security-automation-and-tool-development/waf-and-modsecurity-crs-rule-engineering/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a request path, a matcher set that is false on a patched host, and a template that validates — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Nuclei v3 template schema (`id`, `info`, `http:`, `matchers-condition: and`, `matchers`, `extractors`), `nuclei -validate -t template.yaml`
- **Mandatory Self-Validation Command:** `nuclei -validate -t template.yaml`

1. Confirm the target surface: name the exact endpoint and the response field that only the vulnerable version produces, and record the version range from the vendor advisory.
2. Choose the branch: `http:` GET probe for a disclosure, a `dns:` or `ssl:` probe for infrastructure checks, and `headless:` only when the condition requires rendered DOM.
3. Define the differential: run the template against a vulnerable host and a patched host; the matcher set must fire on the first and not the second. A template that fires on both is a false positive generator.
4. Name the stop condition: `max-redirects`, one request, and `stop-at-first-match: true` when several paths are tried.
5. Prove it: attach the extractor output (version string, header value) and the request that produced it, so the finding does not depend on re-running the scan.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `matchers-condition: and` | Requires all matchers; without it Nuclei applies OR across matchers and a single weak matcher decides the result. |
| `type: dsl with contains(tolower(body), ...)` | Case-insensitive body checks that a plain word matcher cannot express, and the place to exclude SPA shells. |
| `extractors: with type: regex and group: 1` | Pulls the version string out of the response so the report names the version rather than the endpoint. |
| `max-redirects: 0 in http:` | Prevents an off-scope redirect from being followed, which keeps the probe on the assessed host. |

## Worked Contrast

**Status-Only Template That Fires on Catch-Alls:**

```yaml
id: exposed-admin-panel
info:
  name: Admin panel
  severity: info
  author: audit
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status: [200]  # BUG: every SPA returns 200 for /admin
```

**Template Requiring Marker, Status and a Shell Exclusion:**

```yaml
id: exposed-config-metadata
info:
  name: Application config metadata exposed
  severity: low
  author: audit
http:
  - method: GET
    path:
      - "{{BaseURL}}/config.json"
    max-redirects: 0
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: header
        words:
          - application/json
      - type: dsl
        dsl:
          - "contains(body, '\"buildId\"')"
          - "!contains(tolower(body), '<html')"
    extractors:
      - type: regex
        part: body
        regex:
          - '"buildId"\s*:\s*"([^"]+)"'
        group: 1
```

**Why this matters:** A status-only matcher reports every single-page application, because the router answers 200 for any path. Requiring a JSON content type, a body field that only the real endpoint emits, and the absence of an HTML shell makes the match specific to the condition, and the extractor gives the reviewer the build id that proves it.

## When It Is NOT This Issue

- **Matcher fires on a patched version.** A version-range DSL matcher written against the wrong boundary reports patched hosts; verify against a patched instance.
- **Catch-all route answering 200.** Any SPA reports every path as a hit; require a body marker that the shell does not contain.
- **CDN or WAF page substituted.** A block page containing the searched word produces a match that describes the edge, not the origin.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER use deprecated Nuclei v1 `requests:` key — use `http:` in Nuclei v3.
- NEVER match on status `200` alone (`status: [200]` without body/header confirmation causes massive false positives on custom 404/SPA catch-alls).
- NEVER emit state-mutating `DELETE`/`PUT` or destructive payloads in assessment templates.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `nuclei-template-engineering` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: nuclei-template-engineering
- **Target Stack & Schema**: Nuclei YAML schema v3 (`http:` / `dns:` / `ssl:`, `matchers-condition: and`, passive/GET/HEAD non-destructive checks)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `nuclei -validate -t template.yaml`
```

## Related Sub-Skills

- [`waf-and-modsecurity-crs-rule-engineering`](../../../blue-team/security-automation-and-tool-development/waf-and-modsecurity-crs-rule-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`async-http-and-dns-audit-scripting`](../async-http-and-dns-audit-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `nuclei-template-engineering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/nuclei_templates (14), OffsecCyber (8) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
