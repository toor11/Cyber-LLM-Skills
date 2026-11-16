---
name: cross-site-scripting-reflected
description: Reflected cross-site scripting. Covers immediate-reflection XSS through query strings, path segments, headers and error messages, including context detection and encoding-escape payload shaping. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["reflected xss", "non-persistent xss", "reflected cross site"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-stored, cross-site-scripting-dom, cross-site-scripting-mutation]
parent: cross-site-scripting
---

# Cross Site Scripting Reflected - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Reflected XSS echoes a value from the current request into the response of that same request, and the browser parses it as markup or script in whatever context it lands. The security decision is output encoding at the template or render layer, which must match the sink context: HTML text, a quoted attribute, an inline script string, or a URL attribute. The attacker gains script execution in the victim's origin for a single crafted link, with no persistence. Confirmation depends on which context the reflection lands in and whether that context's breaking metacharacters survive encoding.

- **Precondition chain:** a request parameter, path, or header value is reflected into the immediate response, the reflection lands in a context whose breaking metacharacters are not encoded for that context, and the response is served with an HTML or script-executing content type.
- **Readable differential:** a benign marker string versus a context-boundary marker that only adds the delimiter needed to break that sink; a finding exists when the boundary marker appears un-encoded and parses as a new node or attribute, and it closes when the renderer context-encodes that delimiter.
- **Empirical grounding:** CWE-79 covers this class in its immediate-reflection form; OWASP Top 10:2025 folds cross-site scripting into A05:2025 Injection. SOURCES carries no reflected-specific CVE, so the anchor stays at the CWE-79 / OWASP taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to be immediate same-response reflection **THEN** start at parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) (1 hop)
2. **IF** the reflection lands inside a double- or single-quoted HTML attribute value **THEN** treat attribute-escape as the sink and test only the quote and an event-handler name for that context
3. **IF** the reflection lands inside an inline `<script>` block or template literal **THEN** shift to JavaScript-string context and test backtick, backslash, and a literal closing script tag
4. **IF** the value only appears after client-side JavaScript reads it **THEN** route to [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) because the sink is a DOM write, not a server template
5. **IF** the same payload persists and renders for other users later **THEN** route to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md)
6. **IF** a CSP blocks inline execution even though the reflection parses **THEN** route to [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) to assess policy gadgets
7. **IF** a WAF or filter strips angle brackets before the echo **THEN** route to [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`waf-and-web-monitoring`](../../../blue-team/detection-and-monitoring/waf-and-web-monitoring/SKILL.md)
9. **IF** the marker is reflected but context-encoded in every sink and no execution context opens **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Reflection is written by client-side JavaScript, not a server template | [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) | Sink is a DOM API, so encoding must happen in the browser, a different layer |
| Payload persists server-side and renders to other users | [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) | Invariant is encoding on a second-order render path, not the immediate echo |
| Angle brackets survive but a CSP blocks execution | [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) | Remaining work is a policy-gadget bypass, not the reflection itself |
| Need parent class methodology | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the reflection and classify its HTML context.** Send a unique unlikely marker and find every place it echoes; for each, record whether it lands in HTML text, a quoted attribute, an inline script, a URL attribute, or a comment, because the encoding required differs per context.
2. **Choose the context branch from where the marker landed, not from a guess.** A marker inside `value="..."` needs a quote test, one inside an inline script string needs a backslash and closing-tag test, and one in HTML text needs an angle-bracket test.
3. **Record a paired baseline.** Send a benign marker and a near-identical marker differing only by the single delimiter that would break the detected context, keeping method, path, and other parameters constant.
4. **Compare the two reflections in the raw response bytes.** The probe reflection should show the delimiter literally, un-encoded, and introduce a new attribute or node, while the benign marker stays inside its original node.
5. **Confirm the content type actually executes.** A reflection served as text/plain, as JSON, or with correct context-encoding is inert; verify the response Content-Type and that the parser treats the sink as live HTML.
6. **Separate the control from any filter.** If the delimiter is stripped or entity-encoded, attribute it to the right layer (framework auto-escape, WAF, or a template filter) before concluding, since that changes whether the finding is reachable.
7. **Stop condition.** Stop when the probe either (a) breaks the context and introduces an attacker-controlled node that reverts to inert text once the delimiter is context-encoded, (b) is encoded in every landing context across two baselines, or (c) would require delivering the crafted link to a real victim to show impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a single-variable differential: identical request, one changed delimiter, a reflection that parses as new markup in the named context, plus the exact template expression that emits the value without context-aware encoding. A marker that merely appears in the body is not proof until it escapes its node.
9. **Close with the structural fix.** Apply context-aware output encoding at the template layer for the specific sink (HTML-entity for text, attribute-encode inside quotes, JavaScript-string-encode inside scripts), prefer an auto-escaping engine, and verify by replaying the delimiter probe against the patched render.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A unique marker echoed verbatim in the immediate HTTP response body | Proves same-request reflection on any server-rendered stack and establishes the sink exists before any delimiter test |
| The marker landing inside a quoted HTML attribute value | Proves an attribute-context sink where only the quote and an event-handler name break out, not angle brackets |
| The marker landing inside an inline `<script>` string literal | Proves a JavaScript-string sink where backslash, backtick, and a literal closing script tag are the breaking tokens |
| Angle brackets or quotes surviving un-encoded in the reflection | Proves the render layer omits context-aware encoding for that sink on the detected stack |
| Reflection appearing in a `Location`, `Set-Cookie`, or other response header | Proves a header-reflection surface that may be redirect or CRLF-adjacent rather than body XSS |
| A CSP response header present while the reflection still parses as markup | Proves execution may be gated by policy, so impact depends on a CSP gadget rather than the reflection alone |
| Framework auto-escape disabled with a raw or safe filter on the reflected field | Proves the developer opted out of encoding on this sink, the usual root cause on templated stacks |

## Worked Contrast

**Vulnerable pattern:**

```python
from flask import request, Response

def search():
    term = request.args.get("q", "")
    # term is concatenated straight into HTML text with no context encoding
    html = "<h2>Results for " + term + "</h2>"
    return Response(html, mimetype="text/html")
```

**Hardened pattern:**

```python
from flask import request, Response
from markupsafe import escape

def search():
    term = request.args.get("q", "")
    # escape() HTML-entity-encodes the value for the text context it lands in
    html = "<h2>Results for {}</h2>".format(escape(term))
    return Response(html, mimetype="text/html")
```

**Why this matters:** The defective handler concatenates the query into HTML text, so a value containing a tag opens a new node and executes; the fixed handler HTML-entity-encodes the value for its exact context before it reaches the body, so the same input renders as inert text. The control is context-aware output encoding at render time, not input filtering.

## When It Is NOT This Issue

- **Reflected but context-encoded:** the marker appears in the response yet every delimiter is entity-encoded for its context, so it stays inert text. Reflection alone is not CWE-79.
- **Self-only reflected value:** a parameter that only renders back to the sender in a response no one else can be made to request has no victim; a reflected finding needs a deliverable crafted request.
- **Non-executing content type:** the reflection is served as text/plain, application/json, or an attachment, so the browser never parses it as HTML.
- **Encoded by the framework, bypass unproven:** angle brackets are converted to entities by auto-escape with no opt-out on the path; a theoretical double-encoding is not a finding until shown to decode.
- **DOM-only reflection:** the value is placed by client-side JavaScript, not the server template, which is a DOM sink and belongs to dom-based-vulnerabilities.
- **Stored render path:** the value is persisted and shown to other users on a later page, which is stored XSS with a different render path and audience.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-reflected` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-reflected` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-reflected
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-reflected` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 50 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (26), hackerone_disclosed_reports (12), bugbounty-hunter-v1 (5), CYBER_CPT/nuclei_templates (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
