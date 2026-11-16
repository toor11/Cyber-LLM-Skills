---
name: http-method-and-verb-attacks
description: "Exploits HTTP method handling: verb tampering past authorization, method override headers, TRACE and OPTIONS disclosure, and method mismatch between proxy and origin. Use when authorization or routing appears method-dependent."
family: web-and-application
tier: leaf
triggers: ["verb tampering", "method override", "http method bypass", "trace method", "options disclosure"]
cwe: [CWE-650]
owasp: [A01:2021]
attack: []
capec: [CAPEC-274]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Http Method and Verb Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The application makes a security decision based on the HTTP method, but the method the enforcement layer evaluates is not the method the handler ultimately acts on. Authorization rules written for POST or DELETE can be bypassed by an unexpected verb the framework still routes to the same handler, by an `X-HTTP-Method-Override` or `_method` field that rewrites the verb after the gate ran, or by a proxy and origin that disagree on how a method maps to a route. Diagnostic methods such as TRACE and arbitrary verbs can additionally reflect headers or reveal handler behaviour. The security decision is whether authorization is bound to the effective method the handler executes rather than the declared one. Confirmation is a state change or protected response reached through a method the access check did not cover.

- **Precondition chain:** authorization or routing is conditioned on the HTTP method, the effective method the handler acts on can differ from the one the gate evaluated via an unexpected verb, an override header, or a proxy mapping, and the resulting handler performs a protected or state-changing action.
- **Readable differential:** the same request under the method the gate expects versus an overriding or alternate verb that reaches the same handler; a finding exists when the alternate verb performs the action the gate meant to block, and it closes when authorization is evaluated on the effective method.
- **Empirical grounding:** CWE-650 Trusting HTTP Permission Methods on the Server Side, under OWASP Top 10:2025 A01:2025 Broken Access Control. SOURCES.md has no 2025 CVE specific to verb tampering or method override, so this slug stays grounded at the CWE-650 taxonomy level rather than a named advisory.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a route's authorization differs by HTTP method **THEN** test whether an alternate verb reaches the same handler past the gate
2. **IF** the framework honours `X-HTTP-Method-Override` or a `_method` body field **THEN** test whether the override rewrites the verb after authorization ran
3. **IF** a GET variant of a state-changing action is accepted **THEN** treat GET-driven mutation as the primary finding and check CSRF exposure
4. **IF** the mismatch is between a proxy and the origin method mapping **THEN** route the desync angle to [`http-request-smuggling`](../http-request-smuggling/SKILL.md)
5. **IF** the bypass reaches an administrative function by verb **THEN** route the function-level access angle to [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md)
6. **IF** method override enables a cross-site state change **THEN** assess the forgery impact via [`csrf`](../csrf/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** authorization is evaluated on the effective method and every verb to a handler is gated identically **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| An alternate verb reaches an administrative handler | [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) | Invariant is function-level access control independent of the verb used |
| A method-override header enables a cross-site state change | [`csrf`](../csrf/SKILL.md) | Invariant is request-origin binding, not method gating |
| Proxy and origin disagree on method-to-route mapping | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | Invariant is front-end and back-end parsing agreement, a desync class |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate routes whose behaviour depends on the method.** Map each handler and the verbs it accepts, noting where authorization, CSRF defences, or routing branch on the method. A handler that treats all verbs identically is not a candidate.
2. **Identify the effective-method mechanism.** Determine whether the framework derives the acting verb from the request line, an `X-HTTP-Method-Override` or `X-Method-Override` header, or a `_method` form field, and at which layer authorization is evaluated relative to that derivation.
3. **Record a gate-expected baseline.** Send the action under the method the authorization rule expects and capture the allow or deny result, status, and any state change for an authorized and an unauthorized principal.
4. **Send one effective-method divergence.** Keep the path and body identical and change only the verb the handler will act on: an uncovered method, an override header, or a GET form of a mutation, as an unauthorized principal.
5. **Check whether the handler performed the protected action.** Compare the state and response against the baseline to see if the gate was bypassed because it evaluated a different method than the handler executed.
6. **Stop condition.** Stop when the alternate verb either (a) performs the protected or state-changing action the gate meant to block, confirming authorization is bound to the wrong method, (b) is denied identically to the expected method, or (c) would require mutating another user's real data to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a protected action completed through a method the access check did not evaluate, evidenced by the state change or protected response for an unauthorized principal, plus the exact override or routing mechanism that changed the effective verb. A TRACE reflection or an OPTIONS listing alone is information disclosure, not a method-authorization bypass.
8. **Separate disclosure from bypass.** Note whether the finding is a diagnostic-method disclosure (TRACE, verbose OPTIONS) or an authorization bypass, because they have different severities and fixes.
9. **Close with the structural fix and verify.** Evaluate authorization on the effective method after any override resolution, deny unknown verbs by default, disable TRACE and method override unless required, forbid state changes on GET, and align proxy and origin method handling, then replay the alternate-verb probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An authorization rule scoped to POST while the handler also answers PUT or PATCH | Proves the gate covers one verb while the handler acts on several |
| `X-HTTP-Method-Override` or `_method` rewriting the verb after routing | Proves the effective method is set after the authorization check ran |
| A state-changing action reachable by GET | Proves a mutation rides a safe method, enabling forgery and gate bypass |
| TRACE reflecting request headers in the response body | Proves a diagnostic method is enabled, a disclosure surface on the origin |
| An unknown or custom verb routed to a default handler | Proves the router falls through to a handler instead of denying the method |
| Authorization evaluated on the declared verb before override resolution | Proves the check and the effective method can diverge in the framework |
| A proxy translating a method differently from the origin | Proves a front-end and back-end method-mapping disagreement |

## Worked Contrast

**Vulnerable pattern:**

```python
def dispatch(request, user):
    # Authorization checks the request-line verb, but an override header rewrites it later
    if request.method == "GET":
        return render_dashboard(user)
    if request.method == "POST" and not user.is_admin:
        return deny()
    verb = request.headers.get("X-HTTP-Method-Override", request.method)
    return ROUTES[verb](request, user)       # effective verb never re-checked
```

**Hardened pattern:**

```python
SAFE = {"GET", "HEAD", "OPTIONS"}

def dispatch(request, user):
    # Resolve the effective verb first, then authorize on it
    verb = request.headers.get("X-HTTP-Method-Override", request.method).upper()
    if verb not in ROUTES:
        return deny(status=405)
    if verb not in SAFE and not user.is_admin:
        return deny(status=403)
    return ROUTES[verb](request, user)
```

**Why this matters:** The defective dispatcher authorizes on the request-line method and then lets `X-HTTP-Method-Override` pick the handler, so an unauthorized caller sends GET or POST past the check and overrides to a privileged verb; the fixed dispatcher resolves the effective verb first, rejects unknown methods, and authorizes unsafe verbs against the admin role, so the check and the executed method are always the same.

## When It Is NOT This Issue

- **Authorization on the effective method:** a gate that evaluates the verb after override resolution cannot be bypassed by a method header.
- **Uniform per-verb gating:** a handler that applies the same access check to every verb it accepts has no method-dependent gap.
- **TRACE or OPTIONS disclosure only:** a reflected diagnostic method with no authorization bypass is an information-disclosure finding, not a CWE-650 state change.
- **Override header ignored:** a framework that does not honour `X-HTTP-Method-Override` or `_method` cannot have the verb rewritten.
- **Self-only action:** an alternate-verb action confined to the caller's own resource is not a privilege or cross-user bypass.
- **405 on unknown verbs:** a router that denies methods it does not explicitly handle is the control working.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-method-and-verb-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-method-and-verb-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-method-and-verb-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-650 | Mapping: A01:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-method-and-verb-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-650`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/gh_advisories (4), CYBER_CPT/github_security_md (2), CYBER_CPT/atomic_red_team (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
