---
name: csp-and-security-header-bypass
description: Bypasses Content Security Policy and related browser security headers through JSONP endpoints, unsafe-inline gaps, nonce reuse, base-uri and object-src gaps, and script gadgets. Use when XSS is blocked by CSP and you need a working path.
family: web-and-application
tier: leaf
triggers: ["csp bypass", "content security policy", "security header bypass", "nonce reuse", "script gadget"]
cwe: [CWE-693]
owasp: [A05:2021]
attack: []
capec: [CAPEC-63]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# CSP and Security Header Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A Content Security Policy is a response-header allowlist the browser enforces to decide which scripts may run and where content may load, and a bypass finds a path the policy unintentionally permits. Classic gaps are `unsafe-inline` without nonces or hashes, a nonce that is reused or predictable, a missing `base-uri` or `object-src`, an allowlisted origin that serves a JSONP or callback gadget, and directives that do not inherit (`form-action` and `base-uri` are not covered by `default-src`). The security decision is the composition of the policy's directives against the page's actual script and sink inventory, and the attacker gains script execution or credential exfiltration the policy was meant to stop. Confirmation shows a concrete construct the current policy allows, measured against the policy text.

- **Precondition chain:** an injection point or usable gadget exists on the page, the CSP contains a permissive directive or an allowlisted origin hosting a gadget, and a required restricting directive (nonce discipline, base-uri, object-src, or form-action) is missing or bypassable.
- **Readable differential:** the page's actual script and sink inventory versus the CSP directives that should constrain it; a finding exists when a construct the policy permits (allowlisted JSONP, a reused nonce, a missing form-action) executes or exfiltrates, and it closes when the directive that would block it is added.
- **Empirical grounding:** CWE-693 Protection Mechanism Failure. The 2025 anchor is PortSwigger's 'Blind trust: stealing credentials through CSP', which catalogues allowlist gadgets and shows `form-action` not inheriting from `default-src` enabling credential exfiltration with no JavaScript; Trusted Types (`require-trusted-types-for 'script'`) is the complementary enforcement that a pass-through default policy or `trusted-types *` defeats.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the policy contains `unsafe-inline` on script-src with no nonce or hash **THEN** this is the primary gap; inline injection executes directly
2. **IF** a nonce is present but repeats across responses or is guessable **THEN** treat nonce reuse as the finding and confirm two responses share the value
3. **IF** an allowlisted origin hosts a JSONP or callback gadget **THEN** the gadget turns an allowed origin into script execution
4. **IF** the `base-uri` directive is absent **THEN** test base-tag injection that repoints relative script URLs
5. **IF** `object-src` is unset and not covered by default-src **THEN** test plugin or embed sinks the policy leaves open
6. **IF** `form-action` is missing while default-src looks strict **THEN** credential exfiltration via form posts needs no script, since form-action does not inherit
7. **IF** framing rather than script execution is the real concern **THEN** route to [`clickjacking-and-ui-redressing`](../clickjacking-and-ui-redressing/SKILL.md) for frame-ancestors
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`react-nextjs-and-spa-security-architecture`](../../../blue-team/application-security/react-nextjs-and-spa-security-architecture/SKILL.md)
9. **IF** the policy is nonce-based with no unsafe-inline, base-uri/object-src/form-action set, and no allowlisted gadget **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Framing rather than script execution is the risk | [`clickjacking-and-ui-redressing`](../clickjacking-and-ui-redressing/SKILL.md) | Invariant is frame-ancestors, a framing control not a script allowlist |
| The underlying injection is a reflected script context | [`cross-site-scripting-csp-bypass`](../cross-site-scripting-csp-bypass/SKILL.md) | Routes the XSS-plus-CSP chain to the XSS-specific CSP bypass playbook |
| A client-side gadget in app code enables the bypass | [`client-side-security-bypasses`](../client-side-security-bypasses/SKILL.md) | Invariant is a script gadget in first-party code, not the header itself |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Capture the exact policy as served.** Read the `Content-Security-Policy` response header, and any report-only variant, on the target route; the enforced text, not the documentation, is what you test against.
2. **Inventory the page's script and sink surface.** List inline scripts, allowlisted origins, event handlers, base, object, and form usage, and whether nonces or hashes are in play, then classify which directive governs each.
3. **Pick the weakest directive as the branch.** `unsafe-inline`, a reused nonce, a gadget-bearing allowlisted host, a missing `base-uri` or `object-src`, or an absent `form-action` are distinct failures; choose the one the inventory exposes.
4. **Establish a policy-versus-construct baseline.** Record a benign construct the policy clearly blocks, such as a plain inline script with no nonce, and confirm the browser's CSP report fires so enforcement is known to be real.
5. **Probe the suspected gap non-destructively.** For nonce reuse, fetch the route twice and compare nonces; for an allowlisted gadget, point a script source at the known callback endpoint; for a missing form-action, place a form targeting an external collector, each measuring one permitted path.
6. **Confirm the browser honoured the gap, not a filter.** Use the CSP violation reports and the console to see whether the construct was allowed or merely not reached.
7. **Stop condition.** Stop when a construct either (a) executes or exfiltrates under the live policy and is blocked once the missing directive is added, (b) is refused by the browser for every variant you try, or (c) would require stealing a real user's credentials to show impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a specific construct permitted by the current policy text (named directive and gadget) producing execution or a cross-origin send, plus the directive whose absence allowed it. A weak-looking policy with no reachable injection or gadget is not proof.
9. **Close with the structural fix.** Move to a nonce- or hash-based policy with no `unsafe-inline`, set `base-uri 'none'`, `object-src 'none'`, and an explicit `form-action`, remove gadget-bearing origins from the allowlist, add `require-trusted-types-for 'script'`, and verify by replaying each probe against the tightened header.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `script-src` containing `unsafe-inline` with no nonce or hash alongside it | Proves inline injection executes directly on any browser enforcing this policy |
| The same nonce value appearing in two separate responses for a route | Proves nonce reuse, so an attacker can predict and reuse it to satisfy script-src |
| An allowlisted origin that serves a JSONP or callback endpoint | Proves an allowlist gadget that converts a trusted host into arbitrary script execution |
| No `base-uri` directive present in the policy | Proves base-tag injection can repoint relative script URLs despite a script-src allowlist |
| `form-action` absent while default-src appears restrictive | Proves script-free credential exfiltration via form posts, since form-action does not inherit from default-src |
| `object-src` unset and not covered by default-src | Proves plugin or embed sinks remain open on policies that forgot the directive |
| `trusted-types *` or a pass-through default policy with require-trusted-types-for | Proves Trusted Types enforcement is defeated, re-opening DOM-XSS sinks on this stack |

## Worked Contrast

**Vulnerable pattern:**

```python
def add_csp(response):
    # unsafe-inline permits any injected inline script; no base-uri/object-src/form-action
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example"
    )
    return response
```

**Hardened pattern:**

```python
import secrets

def add_csp(response, nonce=None):
    nonce = nonce or secrets.token_urlsafe(16)   # fresh per response, never reused
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'nonce-{}'; "
        "base-uri 'none'; object-src 'none'; form-action 'self'; "
        "require-trusted-types-for 'script'".format(nonce)
    )
    return response
```

**Why this matters:** The defective policy keeps `unsafe-inline` so any injected inline script runs, and omits base-uri, object-src, and form-action so base-tag, plugin, and script-free credential-exfiltration gadgets remain; the hardened policy drops unsafe-inline for a per-response nonce, locks base-uri and object-src, pins form-action, and enables Trusted Types. The control is a gadget-free directive set, not a longer allowlist.

## When It Is NOT This Issue

- **Report-Only policy mistaken for enforcement:** a `Content-Security-Policy-Report-Only` header never blocks anything, so its gaps are not a live bypass of an enforced policy.
- **No reachable injection or gadget:** a permissive-looking policy on a page with no injection point and no allowlisted gadget has nothing to bypass.
- **Nonce unique per response:** a nonce that differs on every fetch and is unguessable satisfies script-src, so a one-time value is not reuse.
- **Allowlisted origin without a gadget:** an allowed host that serves only static assets and no JSONP or callback cannot be turned into script execution.
- **Browser-unsupported directive:** relying on a directive the target browser ignores is a coverage note, not proof the policy is bypassed for supported clients.
- **Framing-only gap:** a missing `frame-ancestors` is a clickjacking question handled elsewhere, not a script-execution CSP bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `csp-and-security-header-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `csp-and-security-header-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: csp-and-security-header-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: A05:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `csp-and-security-header-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 49 |
| Distinct dataset sources | 14 |
| Top sources | hackerone_disclosed_reports (10), CYBER_CPT/nuclei_templates (10), OffsecCyber (9), SecEval/mozilla_security (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
