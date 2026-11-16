---
name: dom-based-vulnerabilities
description: "Finds DOM-based flaws where client-side JavaScript moves attacker input into dangerous sinks: innerHTML, eval, location, postMessage handlers and prototype gadgets. Use when reviewing single-page applications or client-side routing."
family: web-and-application
tier: leaf
triggers: ["dom xss", "dom based", "postmessage", "sink source", "client side injection", "dom clobbering"]
cwe: [CWE-79]
owasp: [A03:2021]
attack: []
capec: [CAPEC-63]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Dom Based Vulnerabilities - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

DOM-based vulnerabilities live entirely in client-side JavaScript: a source the attacker influences (`location.hash`, `location.search`, `document.referrer`, `postMessage` data, `window.name`) flows through the page's own script into a dangerous sink (`innerHTML`, `document.write`, `eval`, `setAttribute`, a `location` assignment) without the server ever rendering the payload. The security decision is made in the browser, so server-side output encoding cannot help and the fix must sanitise or type the value at the sink or use Trusted Types. The attacker gains script execution, open redirect, or DOM clobbering in the victim's session by controlling a source the page trusts. Confirmation traces one source to one sink and shows the value reaching the sink unsanitised in the running page.

- **Precondition chain:** client-side script reads an attacker-influenceable source, passes it to a dangerous DOM sink without sanitisation or a Trusted Types policy, and the page executes that path in the victim's browser.
- **Readable differential:** a benign value in the source versus a value carrying the sink-specific breaking token; a finding exists when the running DOM reflects the token as a new node, navigation, or evaluated code, and it closes when the sink receives a sanitised or typed value.
- **Empirical grounding:** CWE-79 in its DOM-based form, where the data flow never leaves the browser; OWASP Top 10:2025 folds it under A05 Injection. The structural control is Trusted Types (`require-trusted-types-for 'script'`), supported in Chrome and Edge 83+, Safari 26.0+, and Firefox 148+, which forces DOM-XSS sinks to accept only policy-produced values.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an attacker-influenceable source reaches a DOM sink in page script **THEN** this is the primary case; trace the single source-to-sink path
2. **IF** the value is instead rendered by a server template **THEN** route to [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md), where the sink is server-side
3. **IF** the sink is innerHTML fed by a sanitizer whose output is re-parsed **THEN** route to [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md)
4. **IF** the source is a `postMessage` handler with no origin check **THEN** focus on the message event, since the missing `event.origin` check is the defect
5. **IF** the flow ends in a `location` or `location.href` assignment **THEN** treat it as DOM-based open redirect rather than script execution
6. **IF** markup defines named globals that overwrite script variables **THEN** test DOM clobbering via id and name attributes
7. **IF** a CSP would still block the injected inline script **THEN** route to [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`react-nextjs-and-spa-security-architecture`](../../../blue-team/application-security/react-nextjs-and-spa-security-architecture/SKILL.md)
9. **IF** every source reaches its sink through textContent, a sanitizer, or a Trusted Types policy **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Value is placed by a server template | [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) | Sink is server-side output, so the control is template encoding not a DOM API |
| A postMessage handler lacks an origin check | [`client-side-security-bypasses`](../client-side-security-bypasses/SKILL.md) | Invariant is message-origin validation, a client trust boundary distinct from the sink |
| Sanitizer output is re-parsed into the DOM | [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) | Risk is tree mutation on re-parse, not a raw source-to-sink flow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate sources and sinks in the page script.** Grep the loaded JavaScript for sources (`location.hash`, `location.search`, `document.referrer`, `postMessage`, `window.name`) and sinks (`innerHTML`, `document.write`, `eval`, `setAttribute`, a `location` assignment), then list candidate flows.
2. **Trace one concrete source-to-sink path.** Pick a single flow and follow the variable from the source read to the sink call through the real call graph, not a guess, noting any sanitiser or framework binding in between.
3. **Classify the sink and its breaking token.** An innerHTML sink breaks on markup, an eval sink on expression syntax, a location sink on a URL scheme, a setAttribute sink on the attribute name; each has a different probe.
4. **Record a benign baseline through the source.** Put an inert marker in the chosen source, for example the fragment, and confirm where it lands in the live DOM without any breaking character.
5. **Change only the sink-specific token in the source and observe the running DOM.** For innerHTML add an inert tag, for location add a scheme, for eval add an expression delimiter, using the browser's live DOM rather than the HTML response as the oracle.
6. **Confirm nothing between source and sink neutralised the value.** Check for an interposed sanitizer, framework auto-escaping, or a Trusted Types policy that would make the flow safe despite appearances.
7. **Stop condition.** Stop when the probe either (a) makes the live DOM gain an attacker-controlled node, navigation, or evaluated expression that reverts when the sink receives a sanitised or typed value, (b) is neutralised on every traced flow, or (c) would require driving a real victim's browser to the crafted URL to show impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a single traced source-to-sink flow where the running DOM reflects the token as a node, redirect, or evaluated code, plus the exact script line that passes the source to the sink without sanitisation. A source value present in the page but never reaching a sink is not proof.
9. **Close with the structural fix.** Route the value through textContent or a vetted sanitizer at the sink, validate URL schemes before a location assignment, add an `event.origin` allowlist on message handlers, and enforce Trusted Types so DOM-XSS sinks reject raw strings, then replay the source probe in the browser.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `location.hash` or `location.search` read and passed into `innerHTML` | Proves a classic DOM-XSS source-to-sink flow handled entirely in the browser on this SPA |
| A `message` event handler using `event.data` without checking `event.origin` | Proves a cross-origin postMessage trust gap independent of any server control |
| `document.write` or `eval` receiving a value derived from a URL fragment | Proves a high-impact sink where the fragment never reaches the server to be encoded |
| A `location` or `location.href` assignment built from an attacker-influenceable source | Proves a DOM-based open-redirect sink rather than a script-execution sink |
| Markup with attacker-set id or name attributes overwriting script globals | Proves DOM clobbering, where the HTML structure, not a string, subverts the script |
| Absence of a Trusted Types policy on a page using innerHTML sinks | Proves the structural DOM-XSS control is off, so raw strings reach the sink on supported browsers |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Source: URL fragment. Sink: innerHTML. No sanitisation between them.
const tab = decodeURIComponent(location.hash.slice(1));
document.querySelector('#panel').innerHTML = 'Viewing: ' + tab;
// Attacker controls location.hash, so markup in the fragment becomes DOM nodes
```

**Hardened pattern:**

```javascript
// Treat the fragment as text, or route through Trusted Types before a sink
const tab = decodeURIComponent(location.hash.slice(1));
const panel = document.querySelector('#panel');
panel.textContent = 'Viewing: ' + tab;          // text sink: no markup is parsed
// Page also sends: Content-Security-Policy: require-trusted-types-for 'script'
// so any remaining innerHTML sink must receive a TrustedHTML, not a raw string
```

**Why this matters:** The defective script reads the URL fragment and assigns it to innerHTML, so fragment markup becomes live DOM nodes in the victim's browser with no server involvement; the fixed script writes the value with textContent and enables Trusted Types, so the sink cannot parse attacker markup. The control is sink-side typing or sanitisation in the browser, not server encoding.

## When It Is NOT This Issue

- **Source reaches only textContent:** the attacker-influenceable value is written as text, never parsed as markup, so no sink executes.
- **Server-rendered reflection:** the value is placed by a server template, making it reflected XSS with a server-side control, not a DOM flow.
- **postMessage with an origin allowlist:** a handler that checks `event.origin` against an allowlist before using `event.data` closes the cross-origin source.
- **Framework-bound interpolation:** React or Angular text binding escapes by default, so a value in an expression is not a DOM sink unless a bypass API is used.
- **Source present but never sinked:** a fragment or query value read into a variable that is logged or compared, never reaching a dangerous sink, is inert.
- **Trusted Types enforced:** a page enforcing `require-trusted-types-for 'script'` rejects raw strings at DOM-XSS sinks on supported browsers.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `dom-based-vulnerabilities` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `dom-based-vulnerabilities` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: dom-based-vulnerabilities
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79 | Mapping: A03:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `dom-based-vulnerabilities` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 43 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (23), hackerone_disclosed_reports (6), CYBER_CPT/github_security_md (3), CYBER_CPT/ctf_search (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
