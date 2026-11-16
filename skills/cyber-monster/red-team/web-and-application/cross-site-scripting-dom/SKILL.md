---
name: cross-site-scripting-dom
description: "DOM-based cross-site scripting. Covers source-to-sink flows in client-side JavaScript: location and hash sources, postMessage handlers, innerHTML and eval sinks, and framework-specific dangerous bindings. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: web-and-application
tier: leaf
triggers: ["dom xss", "dom based xss", "client side xss", "source sink"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-reflected, cross-site-scripting-stored, cross-site-scripting-mutation]
parent: cross-site-scripting
---

# Cross Site Scripting Dom - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The vulnerability lives entirely in client-side JavaScript: a DOM source the attacker influences, location.hash, location.search, document.referrer, or a postMessage event, flows through the script into a dangerous sink such as innerHTML, outerHTML, document.write, or eval, with no safe transformation in between. The server may never see the payload, because a fragment after the hash is not sent, so this is a source-to-sink taint problem in the page's own code. The security decision is which sink the tainted value reaches and whether it is assigned as a string that the parser treats as markup. The attacker gains script execution in the page origin just as with server XSS, but the proof is a traced data flow plus browser execution, not a reflected response. Confirmation pairs the specific source and sink and shows the value executing.

- **Precondition chain:** A DOM source carries attacker-influenced data, client-side script passes it to a string-to-markup or code sink without sanitization, the browser parses the assigned string as active content, and the page origin holds a session or action worth stealing.
- **Readable differential:** A benign value in the DOM source rendered inertly versus a value that, assigned to the sink, parses as markup; a finding exists when the sink executes the value in the browser, and it reverts once the sink uses a text or typed API such as textContent or Trusted Types.
- **Empirical grounding:** CWE-79 under OWASP Top 10:2025 A05:2025 Injection; CVE-2025-15599 and CVE-2026-0540 (DOMPurify mXSS) show client-side sanitizer bypasses feeding DOM sinks, the client-side class this variant isolates.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a client-side source-to-sink flow **THEN** start at the parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) first
2. **IF** the source is server-reflected rather than read from the DOM **THEN** reclassify as reflected and read [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md)
3. **IF** the sink is reached by polluting Object.prototype first **THEN** treat the prototype gadget and read [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md)
4. **IF** the flow is a non-script client-side source and sink **THEN** reclassify as a client-side taint issue and read [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md)
5. **IF** the tainted value arrives via a postMessage handler **THEN** verify the handler's origin check before treating the sink as the whole finding
6. **IF** a client-side sanitizer runs and the break is a parser mutation **THEN** test the sanitizer output as an mXSS mutation rather than a raw assignment
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no DOM source reaches a markup or code sink after tracing the script **THEN** STOP and record a verified non-finding rather than assuming a client-side flaw

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Source is server-reflected, not DOM-read | [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) | Routes to server-side reflection rather than a DOM source |
| Sink reached through prototype pollution | [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) | Invariant is prototype integrity feeding a DOM sink |
| Non-script client-side source and sink | [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) | Invariant is broader client-side taint beyond script execution |
| Need parent class methodology | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the DOM sources the page reads.** Grep the client bundles for location.hash, location.search, document.referrer, document.cookie, and window message listeners, recording each read.
2. **Trace each source to a sink.** Follow the tainted variable through the script to any innerHTML, outerHTML, document.write, insertAdjacentHTML, or eval assignment, noting whether a sanitizer or encoder sits in the path.
3. **Classify the sink as string-to-markup or code.** A sink that assigns a raw string the parser treats as HTML or executes as code is the decision point; a text sink like textContent is not.
4. **Record an inert-source baseline.** Set the source to a benign token and observe the DOM to confirm the value reaches the sink as data before attempting a break.
5. **Apply the source-to-sink differential in a browser.** Supply a value that would parse as markup only if the sink is unsafe, and confirm execution in the page, selecting the finding from a rendered callback rather than from server output.
6. **Stop condition.** Halt when the probe either (a) executes through the traced sink and reverts once the sink uses textContent or Trusted Types, (b) reaches only a text sink or is sanitized in the path, or (c) affects only the attacker's own browser state. Case (a) confirms, (b) is a non-finding, (c) is self-only.
7. **State what counts as proof.** Proof is a named DOM source flowing to a named markup or code sink with browser execution shown by a benign controlled signal, plus the exact script line of the sink assignment. A source that never reaches a dangerous sink is not proof.
8. **Close with the structural fix and verify.** Replace the markup sink with textContent or a Trusted Types policy, validate postMessage origins, and sanitize with an mXSS-aware library, then re-run the source-to-sink probe and confirm the value renders inert.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| location.hash or location.search read into a variable | Proves a client-side taint source that never reaches the server on the page's own stack |
| A tainted value assigned to innerHTML or outerHTML | Proves a string-to-markup sink where assignment parses the value as active HTML |
| document.write called with a URL-derived value | Proves a document-stream sink that injects markup during parsing on the client |
| eval or new Function fed a DOM-sourced string | Proves a code sink where the client compiles attacker-influenced text in the page origin |
| A postMessage handler using event.data without an origin check | Proves a cross-window source feeding a sink without validating the sender origin |
| A DOMPurify version in the 3.1.x to 3.2.6 range before a sink | Proves an mXSS-exposed sanitizer where re-parsed output can execute per the DOMPurify advisories |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// hash fragment flows straight into a string-to-markup sink
const view = document.getElementById("view");
view.innerHTML = decodeURIComponent(location.hash.slice(1));
```

**Hardened pattern:**

```javascript
// textContent keeps the value as data; a Trusted Types policy blocks raw innerHTML
const view = document.getElementById("view");
view.textContent = decodeURIComponent(location.hash.slice(1));
```

**Why this matters:** The vulnerable line assigns a hash-derived string to innerHTML, so the browser parses attacker markup as active content. The fix assigns the value through textContent, which the parser treats strictly as text, and pairs with a Trusted Types policy so no raw-string innerHTML sink remains reachable.

## When It Is NOT This Issue

- **Sink is textContent or innerText:** a tainted value assigned to a text sink is rendered as data and cannot execute.
- **Framework auto-escaping binding:** a value rendered through a framework text interpolation, not a raw-HTML binding, is encoded by the framework.
- **postMessage origin validated:** a handler that checks event.origin against an allowlist before using event.data is not an open source.
- **Source never reaches a dangerous sink:** a hash or search value read but only compared or stored has no markup or code sink.
- **Trusted Types enforced:** a page with require-trusted-types-for 'script' rejects raw-string sink assignments, blocking the flow.
- **Self-only DOM change:** a value that alters only the attacker's own rendered page with no cross-user reach is not reportable.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-dom` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-dom` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-dom
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-dom` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 29 |
| Distinct dataset sources | 8 |
| Top sources | hackerone_disclosed_reports (12), OffsecCyber (6), CYBER_CPT/hacktricks (3), CYBER_CPT/ctf_search (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
