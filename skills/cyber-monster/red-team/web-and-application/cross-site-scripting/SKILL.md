---
name: cross-site-scripting
description: Finds and exploits cross-site scripting in reflected, stored, DOM and mutation contexts, including filter and CSP bypass, framework-specific sinks, and session or CSRF-token theft chains. Use when user input is rendered into HTML, attributes, JavaScript, CSS or URLs.
family: web-and-application
tier: flagship
triggers: ["xss", "cross-site scripting", "cross site scripting", "script injection", "html injection", "dom xss"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting-reflected, cross-site-scripting-stored, cross-site-scripting-dom, sql-injection]
---

# Cross Site Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **flagship** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

User-controlled input is placed into a page without encoding for the exact output context, so the browser parses attacker bytes as markup, script, an event handler, or a URL scheme instead of as text. The break is contextual: the same value is safe in HTML text but dangerous unencoded in an attribute, a script block, a style, or a javascript: URL, and server-side reflected, stored, DOM, and mutation flows each reach that parse differently. The security decision is output encoding and sink typing at render time, not input blocklisting. The attacker gains script execution in the victim's origin, which yields session and CSRF-token theft or actions on the victim's behalf. Confirmation requires execution in a real browser context, not mere reflection of the string in the response.

- **Precondition chain:** Attacker input reaches a rendered page, the output context does not encode it for that context, the browser parses it as active content rather than text, and the script runs in an origin whose session or actions are valuable.
- **Readable differential:** A unique benign marker rendered as inert text versus the same marker in a context-breaking form; a finding exists when the breaking form parses as active content in a browser, and it reverts to inert text once the value is encoded for its output context.
- **Empirical grounding:** CWE-79 under OWASP Top 10:2025 A05:2025 Injection; CVE-2025-15599 and CVE-2026-0540 (DOMPurify mXSS) and CVE-2025-6430 (Firefox Content-Disposition bypass via iframe srcdoc, fixed 140.0.2) are 2025-2026 instances of context and sanitizer breaks.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the input is reflected straight back in the immediate response **THEN** switch to [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) (1 hop)
2. **IF** the input is persisted and served to other users later **THEN** switch to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) (1 hop)
3. **IF** the sink is in client-side JavaScript reading a DOM source **THEN** switch to [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) (1 hop)
4. **IF** a sanitizer is present and the break is a parser mutation **THEN** switch to [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) (1 hop)
5. **IF** a tag or attribute blocklist stands between input and sink **THEN** switch to [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md) (1 hop)
6. **IF** a Content-Security-Policy blocks inline script **THEN** switch to [`cross-site-scripting-csp-bypass`](../cross-site-scripting-csp-bypass/SKILL.md) (1 hop)
7. **IF** the payload only fires later in an admin, log, or PDF viewer **THEN** switch to [`cross-site-scripting-blind-and-oob-xss`](../cross-site-scripting-blind-and-oob-xss/SKILL.md) (1 hop)
8. **IF** the execution is driven by Object.prototype pollution feeding a sink **THEN** treat it as a prototype gadget and read [`prototype-pollution`](../prototype-pollution/SKILL.md)
9. **IF** the flow is a non-script client-side source and sink **THEN** reclassify as a client-side taint issue and read [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md)
10. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
11. **IF** the marker renders only as inert encoded text in every context **THEN** STOP and record a verified non-finding rather than reporting reflection

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Payload fires only in an admin, log, or PDF viewer | [`cross-site-scripting-blind-and-oob-xss`](../cross-site-scripting-blind-and-oob-xss/SKILL.md) | Routes to callback-confirmed deferred execution, a different oracle |
| Execution rides Object.prototype pollution | [`prototype-pollution`](../prototype-pollution/SKILL.md) | Invariant is prototype integrity feeding a gadget sink |
| Non-script client-side source and sink | [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) | Invariant is broader client-side taint beyond script injection |
| Target matches `cross-site-scripting-reflected` | [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cross-site-scripting-stored` | [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cross-site-scripting-dom` | [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cross-site-scripting-mutation` | [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cross-site-scripting-filter-and-context-bypass` | [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cross-site-scripting-csp-bypass` | [`cross-site-scripting-csp-bypass`](../cross-site-scripting-csp-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine the exact output context of the sink.** Locate where the value lands, HTML text, a quoted or unquoted attribute, inside a script block, a style, or a URL scheme, because the context dictates both the break and the correct encoding.
2. **Classify the flow type.** Decide from evidence whether the value is reflected, stored, assembled in the DOM, or mutated by a sanitizer, since each reaches the parser by a different path and routes to a different child skill.
3. **Choose a unique inert marker as the oracle.** Use a distinctive token first to find where the value lands and how it is encoded, before any context-breaking character, so reflection is separated from execution.
4. **Record how the marker is encoded per context.** Note whether angle brackets, quotes, or the javascript: scheme survive, giving the baseline against which a break is measured.
5. **Apply the context-matched break differential.** Introduce only the minimal character that breaks the identified context and confirm execution in a real browser, not reflection, selecting the finding from a rendered callback rather than a string match.
6. **Stop condition.** Halt when the probe either (a) executes in a browser and reverts to inert text once the value is context-encoded, (b) renders only as encoded text in every context, or (c) affects only the attacker's own session with no cross-user reach. Case (a) confirms, (b) is a non-finding, (c) is a self-only non-finding.
7. **State what counts as proof.** Proof is script execution in the victim's origin, shown by a benign in-browser signal such as a controlled DOM change or an authorised callback, tied to one context-breaking marker, plus the sink and its missing encoding. Reflection of the raw string alone is not proof.
8. **Close with the structural fix and verify.** Apply context-aware output encoding at the sink, prefer safe sink APIs such as textContent, and layer a nonce-based CSP, then re-render the marker and confirm it stays inert text in a browser.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A unique marker reflected with angle brackets intact in HTML text | Proves an HTML-context sink missing entity encoding on the rendering stack in use |
| A marker breaking out of a quoted attribute into a new event handler | Proves an attribute-context encoding gap where quote handling is the deciding control |
| Input landing inside a script block and closing the string literal | Proves a JavaScript-context sink where HTML encoding alone does not neutralise the break |
| A javascript: or data: URL accepted in an href or src attribute | Proves a URL-scheme sink where scheme allowlisting, not HTML encoding, is the needed control |
| A sanitizer output that a browser re-parses into executable markup | Proves a mutation break, the class behind the DOMPurify mXSS advisories |
| Execution confirmed by a controlled DOM change in a real browser | Proves active content rather than reflection, the bar for a genuine XSS finding |
| A stolen CSRF token or session cookie reachable from the executing script | Proves cross-user impact on any origin whose tokens the script can read |

## Worked Contrast

**Vulnerable pattern:**

```python
from markupsafe import Markup

def profile_page(req):
    bio = req.params.get("bio", "")
    # Markup marks attacker HTML as safe, disabling the template autoescape
    return render_template("profile.html", bio=Markup(bio))
```

**Hardened pattern:**

```python
import bleach

ALLOWED_TAGS = ["b", "i", "em", "strong", "a"]
ALLOWED_ATTRS = {"a": ["href"]}

def profile_page(req):
    bio = req.params.get("bio", "")
    # autoescape stays on; rich text is reduced to a fixed tag and attribute set
    clean = bleach.clean(bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
    return render_template("profile.html", bio=clean)
```

**Why this matters:** The vulnerable handler wraps attacker HTML in Markup, which tells the template engine to skip autoescaping, so any script tag renders live. The fix keeps autoescaping on and sanitizes rich text down to a closed tag and attribute allowlist, so only inert formatting survives into the page.

## When It Is NOT This Issue

- **Self-XSS only:** a payload that executes solely in the attacker's own authenticated view, requiring the victim to paste it themselves, has no cross-user impact.
- **Reflected but encoded:** a marker returned as entity-encoded text in every context is being handled correctly and does not execute.
- **HttpOnly cookie with no other impact:** if the only asset is an HttpOnly session cookie the script cannot read and no sensitive action is reachable, the impact story is incomplete.
- **Framework autoescaping intact:** a modern template that encodes by default renders the marker inert unless a raw or safe marker was explicitly used.
- **Non-HTML response type:** a value echoed in a JSON or text/plain response with a correct content type is not parsed as markup by the browser.
- **WAF blocks before the sink:** a probe rejected by a filter is the filter working, not proof the underlying sink is safe or unsafe.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 73 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (35), CYBER_CPT/nuclei_templates (13), hackerone_disclosed_reports (11), SecEval/cwe (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 1 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
