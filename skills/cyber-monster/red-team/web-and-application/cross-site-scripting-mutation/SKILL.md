---
name: cross-site-scripting-mutation
description: Mutation XSS via parser differentials. Covers mXSS where server-side sanitization and browser parsing disagree, including namespace confusion, foreign content, and DOMPurify bypass patterns. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["mutation xss", "mxss", "parser differential", "dompurify bypass", "sanitizer bypass"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-reflected, cross-site-scripting-stored, cross-site-scripting-dom]
parent: cross-site-scripting
---

# Cross Site Scripting Mutation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Mutation XSS defeats an HTML sanitizer that is correct at the string level but whose output is re-parsed by the browser into a different tree than the sanitizer saw. The sanitizer validates a parse tree and serialises it back to a string; when the browser or an innerHTML assignment re-parses that string under different rules (foreign content in `<svg>` or `<math>`, namespace confusion, attribute re-interpretation, template or noscript quirks) benign-looking markup mutates into an executing node. The security decision is that the string the sanitizer blessed must deserialise to the same tree, and the attacker gains script execution despite a sanitizer being present. Confirmation compares the submitted markup against what the element actually serialises to after insertion.

- **Precondition chain:** user HTML passes through a server- or client-side sanitizer, the sanitised string is later re-parsed by the browser via innerHTML or an equivalent, and that re-parse yields a different tree than the sanitizer approved for at least one construct.
- **Readable differential:** the sanitised string the application stored versus the element's serialised innerHTML after insertion; a finding exists when the two differ in a way that introduces an executable node, and it closes when a current sanitizer version is used and the blessed output is never re-parsed or mutated afterwards.
- **Empirical grounding:** CWE-79 in its mutation-XSS form. The 2025 anchors are CVE-2025-15599 (DOMPurify mXSS, 3.1.3 to 3.2.6 and 2.5.3 to 2.5.8, fixed 3.2.7 / 2.5.9) and CVE-2026-0540 (DOMPurify mXSS reported for the 2.5.x range), both showing a stale sanitizer re-serialising to an executing tree.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to have a sanitizer plus a re-parse **THEN** start at parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) (1 hop)
2. **IF** no sanitizer runs and the markup is emitted raw **THEN** route to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) because the issue is missing encoding, not mutation
3. **IF** the sink is a client-side innerHTML assignment reading attacker input **THEN** route to [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) for the DOM-sink mechanics
4. **IF** the mutation rides inside `<svg>` or `<math>` foreign content **THEN** focus the probe there, since foreign-content namespace switching is the classic mXSS trigger
5. **IF** the sanitizer version is unknown **THEN** fingerprint the DOMPurify or sanitizer version first, because a patched build changes the conclusion
6. **IF** a CSP would still block the mutated inline script **THEN** route to [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) to see whether policy saves it
7. **IF** the mutation appears only after a second sanitise or re-serialise cycle in the app **THEN** test the re-parse loop the application itself performs
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`react-nextjs-and-spa-security-architecture`](../../../blue-team/application-security/react-nextjs-and-spa-security-architecture/SKILL.md)
9. **IF** a current sanitizer version is used and the blessed output is inserted without re-parsing or post-mutation **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No sanitizer present; markup emitted verbatim | [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) | Invariant is output encoding, not sanitizer re-parsing |
| Attacker input reaches innerHTML in client JavaScript | [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) | Sink is a DOM write and the mutation is a property of that sink |
| Mutated node is still blocked by policy | [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) | Remaining control is CSP, a separate layer from the sanitizer |
| Need parent class methodology | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm a sanitizer actually runs and identify it and its version.** Mutation XSS only exists where something sanitises; locate the library (commonly DOMPurify) and read its version, because the affected range decides reachability.
2. **Locate the re-parse point.** Find where the sanitised string is turned back into DOM, such as an innerHTML assignment, a framework `dangerouslySetInnerHTML`, or a second sanitise pass, because the mutation happens on re-parse, not at sanitise time.
3. **Record a baseline serialisation.** Submit benign markup, let it pass the sanitizer, insert it, and read the element's serialised output; this is the tree the browser actually built.
4. **Submit a foreign-content probe.** Use a construct known to mutate across the parse boundary (`<svg>` or `<math>` wrapping, namespace or attribute confusion) that the sanitizer accepts as inert, alongside a benign control.
5. **Define the differential precisely.** Compare the sanitised string the application holds against the serialised DOM after insertion; equality means no mutation, while divergence that yields an executable node is the signal.
6. **Attribute the divergence to a stale or misconfigured sanitizer.** Confirm whether upgrading the library version, or removing a post-sanitise mutation the app performs, eliminates the divergence.
7. **Stop condition.** Stop when the probe either (a) produces a serialised tree containing an executable node that a current sanitizer version no longer yields, (b) serialises identically to the submitted string across controls, or (c) would require chaining to live script execution against a real user. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a byte-level mismatch between the sanitised input and the element's post-insertion serialisation that introduces a script-capable node, plus the sanitizer name and affected version. A payload the sanitizer strips, or that serialises back unchanged, is not proof.
9. **Close with the structural fix.** Upgrade the sanitizer to a fixed release (sanitizer version discipline) and never mutate or re-parse its output afterwards; where possible assign via textContent or a Trusted Types policy, then re-run the serialisation differential on the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A sanitizer such as DOMPurify present in the client bundle at a pre-fix version | Proves the mutation precondition on a JavaScript stack, where the affected version range is the reachability test |
| Sanitised HTML re-assigned through innerHTML or dangerouslySetInnerHTML | Proves a re-parse point where the blessed string is rebuilt into a possibly different tree |
| `<svg>` or `<math>` foreign-content wrappers around otherwise inert markup | Proves a namespace-switch construct, the classic trigger for tree mutation on re-parse |
| The element's serialised innerHTML differing from the submitted sanitised string | Proves the browser built a different tree than the sanitizer approved, the core mXSS signal |
| The application running a second sanitise or transform after the first | Proves an app-induced re-serialisation loop that can resurrect executable nodes |
| Attributes re-interpreted after insertion such as style or namespaced attributes | Proves attribute-level mutation independent of element-level sanitisation on this renderer |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Sanitised once, then re-parsed by innerHTML, where mutation re-introduces script
const clean = DOMPurify.sanitize(userHtml);   // DOMPurify pinned at a pre-fix version
document.querySelector('#bio').innerHTML = clean;
// No version floor, and the blessed string is re-parsed on assignment
```

**Hardened pattern:**

```javascript
// Keep the sanitizer current and do not re-parse its output into a different tree
import DOMPurify from 'dompurify';   // pinned to a fixed release (>= 3.2.7)

const clean = DOMPurify.sanitize(userHtml, { RETURN_TRUSTED_TYPE: true });
// Assign via a Trusted Types sink so the blessed value is not silently re-parsed
document.querySelector('#bio').innerHTML = clean;
// Enforced by: Content-Security-Policy: require-trusted-types-for 'script'`
```

**Why this matters:** The defective code pins a pre-fix DOMPurify and feeds its output straight into innerHTML, where foreign-content mutation can rebuild an executing node; the fixed code upgrades to a release that closes the mXSS class and routes the value through Trusted Types so the sanitised output is not re-parsed into a different tree. The control is sanitizer version discipline plus refusing to mutate blessed output.

## When It Is NOT This Issue

- **Sanitizer strips the construct:** the foreign-content payload is removed outright by a current sanitizer, so no tree survives to mutate. A blocked payload is not mXSS.
- **No re-parse of blessed output:** the sanitised string is assigned via textContent or rendered as text, never re-parsed as HTML, so mutation has no trigger.
- **Serialises back identically:** the submitted markup and the post-insertion serialisation match byte-for-byte, and without divergence there is no mutation.
- **Patched sanitizer version:** the library is at or above the fixed release for the reported mXSS class, so the known mutation no longer occurs.
- **Server-sanitised then displayed as text:** HTML is neutralised server-side and shown escaped, so the browser never builds a live tree from it.
- **Mutation without a script-capable node:** the tree changes but only into inert elements with no event handler or script context, which is a cosmetic diff, not execution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-mutation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-mutation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-mutation
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
- [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-mutation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/gh_advisories (3), CYBER_CPT/osv (3), CYBER_CPT/pentesterlab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
