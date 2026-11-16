---
name: prototype-pollution-client-side-gadgets
description: Client-side prototype pollution gadgets. Covers DOM gadget chains that turn pollution into XSS or script execution, using automated gadget discovery and manual verification. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["client side prototype pollution", "dom pollution gadget", "pp gadget xss"]
cwe: [CWE-1321]
owasp: [A08:2021]
attack: []
capec: [CAPEC-460]
related: [prototype-pollution, prototype-pollution-server-side, prototype-pollution-rce-chains, sql-injection]
parent: prototype-pollution
corpus_sparse: true
---

# Prototype Pollution Client Side Gadgets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

The client-side variant pollutes the browser's own prototype from a source the page controls, such as location.hash or search parsed by a vulnerable URL-param-to-object routine, postMessage data merged into config, or a JSON blob deep-merged in the browser. A gadget is any library code that reads an undefined property and routes it to a DOM sink: jQuery extend, a sanitizer's config, a template srcdoc or src, or a script-loader attribute. Polluting that property turns into script execution without the app intending the attribute. The security decision is the client-side recursive merge plus a gadget that reads the polluted key into a sink, and whether Trusted Types or a strict CSP would block the resulting injection.

- **Precondition chain:** a client-side sink merges attacker-influenced data into objects without a prototype guard, a gadget in loaded script reads an unset property and routes it to a DOM or script sink, the page runs without Trusted Types or a strict CSP that would block the injection, and the pollution source such as hash, query, or postMessage is reachable.
- **Readable differential:** load the page with a __proto__-setting fragment versus a benign fragment; a gadget fires only with the pollution fragment and stops once the merge is guarded or Trusted Types is enforced.
- **Empirical grounding:** This maps to CWE-1321 under OWASP Top 10:2025 A08; SOURCES.md has no client-side prototype-pollution CVE, so grounding stays at taxonomy, with Trusted Types enforcement via require-trusted-types-for 'script' noted from the sources as the structural control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to merge client-side input into objects **THEN** start at parent class [`prototype-pollution`](../prototype-pollution/SKILL.md) (1 hop) to confirm a browser merge sink
2. **IF** the pollution source is location.hash or the query string **THEN** set __proto__[canary] through the fragment and check ({}).canary in the console
3. **IF** the pollution source is postMessage data merged into config **THEN** post a __proto__ payload from a test origin and observe the gadget
4. **IF** a gadget scanner flags a property read that reaches innerHTML **THEN** prefer the innerHTML or srcdoc gadget because it needs no user interaction
5. **IF** a loaded bundle reads a script src or href default you can pollute **THEN** test the script-loader gadget, which upgrades pollution to script execution
6. **IF** the page enforces Trusted Types or a strict script-src CSP **THEN** record the policy, since enforcement closes the DOM sink even if pollution succeeds
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** pollution succeeds but no gadget reads the key into a sink **THEN** STOP and classify as a non-exploitable finding rather than claiming XSS

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The polluted key lands in a DOM injection sink | [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) | The exploited bug is a DOM XSS sink, a different invariant than the prototype write |
| The source-to-sink flow needs full mapping | [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) | Focus is the taint path from client source to sink, not prototype mutation |
| A gadget reaches a sink despite a content security policy | [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) | Invariant becomes CSP gadget bypass rather than the pollution itself |
| Need parent class methodology | [`prototype-pollution`](../prototype-pollution/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Confirm browser-side pollution with an inert canary, for example __proto__[cg_canary]=yes in the fragment, then read ({}).cg_canary in the console.
2. Enumerate gadgets in loaded bundles that read a property you can pollute, preferring those that reach a DOM or script sink.
3. Prefer no-interaction sinks: script src, srcdoc, innerHTML, or href, because they fire on load.
4. Choose the branch from evidence: which gadget library is present (jQuery extend, a sanitizer config, a loader) determines the key you set.
5. Define the baseline-versus-probe differential: load with a benign fragment versus the pollution fragment and observe the gadget only in the second case.
6. Verify in a real browser rather than a DOM parser, since gadget behaviour depends on the actual runtime.
7. **Stop condition.** Stop when (a) a DOM element gains an attacker-set attribute from a fresh object, proving the gadget fires inertly, (b) the canary sets but no gadget reads it, or (c) advancing would require a live cross-site scripting payload; (a) is confirmation, (b) is non-exploitable, (c) is out of scope.
8. **State what counts as proof.** Proof is a created element carrying an attacker-set attribute read from an unset default, reverting when the merge is guarded or Trusted Types is enforced. Close with guarding keys client-side, adopting require-trusted-types-for 'script', freezing Object.prototype, and re-running the fragment probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| location.hash parsed into a nested object | Proves a client-side pollution source reachable without a request to the server |
| jQuery extend(true, ...) applied to URL parameters | Proves a recursive merge gadget in the page's own libraries |
| A fresh empty object carrying cg_canary in DevTools | Proves browser-side prototype pollution rather than a local own-property set |
| A sanitizer honoring a polluted config key | Proves a gadget path from pollution to a DOM sink |
| require-trusted-types-for 'script' absent from the CSP | Proves the script sink is reachable because enforcement is off |
| A script element gaining src from an unset default | Proves a loader gadget that upgrades pollution to script execution |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// URL fragment merged into config without guarding __proto__.
const cfg = {};
deepMerge(cfg, parseFragment(location.hash));   // attacker sets Object.prototype.src

const s = document.createElement("script");
s.src = cfg.src || "/app.js";   // gadget reads a default it never set -> attacker URL
document.body.appendChild(s);
```

**Hardened pattern:**

```javascript
// Trusted Types enforce script URLs; the merge refuses prototype keys.
// Response header: Content-Security-Policy: require-trusted-types-for 'script'
const policy = trustedTypes.createPolicy("appLoader", {
  createScriptURL: (u) => new URL(u, location.origin).origin === location.origin
    ? u : (() => { throw new Error("cross-origin script blocked"); })(),
});

const cfg = Object.create(null);
safeMerge(cfg, parseFragment(location.hash));   // __proto__ and constructor skipped

const s = document.createElement("script");
s.src = policy.createScriptURL(cfg.src || "/app.js");
document.body.appendChild(s);
```

**Why this matters:** The defect merges fragment data into a plain object, so __proto__.src sets a default the loader gadget reads, yielding an attacker-controlled script. The fix builds a null-prototype config, skips prototype keys in the merge, and routes the script URL through a Trusted Types policy that only permits same-origin scripts, so a polluted default cannot load foreign code.

## When It Is NOT This Issue

- **Trusted Types enforced:** require-trusted-types-for 'script' blocks the DOM sink even if the prototype is polluted.
- **Strict CSP:** a script-src that forbids the injected origin stops the loader gadget from executing.
- **No gadget reads the key:** pollution that no loaded code consumes into a sink is not exploitable.
- **Own-property only:** a canary set on the target object but not on a fresh object is not prototype pollution.
- **Framework using Map or null prototypes:** a page whose libraries avoid the prototype chain has no gadget surface.
- **Sandboxed iframe with no sink:** pollution confined to an iframe that has no DOM or script sink yields no execution.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `prototype-pollution-client-side-gadgets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prototype-pollution-client-side-gadgets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: prototype-pollution-client-side-gadgets
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1321 | Mapping: A08:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`prototype-pollution`](../prototype-pollution/SKILL.md) - Web and Application (core)
- [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) - Web and Application (leaf)
- [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prototype-pollution-client-side-gadgets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/hacktricks (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
