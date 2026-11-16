---
name: authentication-bypass-forced-browsing
description: Authentication bypass through forced browsing and path tricks. Covers reaching protected resources directly with path normalization, case, extension and trailing-slash tricks and alternate entry points that skip the auth filter. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["forced browsing", "path auth bypass", "filter skip", "unauthorized access"]
cwe: [CWE-287]
owasp: [A07:2021]
attack: [T1078]
capec: [CAPEC-115]
related: [authentication-bypass, authentication-bypass-response-manipulation, authentication-bypass-default-and-weak-credentials, authentication-bypass-header-and-proxy-trust]
parent: authentication-bypass
---

# Authentication Bypass Forced Browsing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Forced browsing defeats authentication by requesting a protected resource directly while the component that enforces the gate never sees the request in the form it will ultimately be routed as. The classic cause is a normalisation disagreement: the auth filter matches on the raw path string with a case-sensitive prefix or an exact literal, while the router resolves `/Admin`, `/admin/.`, `/admin%2f`, a double slash, or an appended `.json` to the same protected handler after the filter has already passed. Alternate entry points behave the same way, where a static alias or legacy route serves gated content that was never placed behind the filter. The attacker reaches authenticated-only functionality with no credential, and confirmation is a path variant that returns protected content where the canonical path returns a login redirect or 401.

- **Precondition chain:** a resource is meant to require authentication, the enforcement matches a path form that differs from the form the router finally dispatches, and a reachable variant resolves to the protected handler without passing the gate.
- **Readable differential:** the canonical protected path versus a normalised or aliased variant of it, both unauthenticated; a finding exists when the variant returns protected content while the canonical path returns 401 or a redirect, and it closes once the gate matches on the post-routing canonical path.
- **Empirical grounding:** CWE-287 Improper Authentication together with CWE-425 Direct Request (Forced Browsing); OWASP Top 10:2025 A01 Broken Access Control explicitly lists forced browsing within its scope, making the canonicalisation-before-authorisation rule the anchoring control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match forced browsing **THEN** start at parent class [`authentication-bypass`](../authentication-bypass/SKILL.md) (1 hop) for general triage
2. **IF** the protected path responds differently to case changes such as /Admin **THEN** test case-sensitivity of the filter against the canonical path
3. **IF** a dot segment, double slash, or encoded separator resolves to the handler **THEN** treat it as a normalisation disagreement between filter and router
4. **IF** an appended extension such as .json reaches the same controller **THEN** test suffix stripping that happens after the filter runs
5. **IF** the reached endpoint is an admin function rather than an unauthenticated area **THEN** reclassify as function-level access and read [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md)
6. **IF** the bypass depends on the proxy and origin normalising URLs differently **THEN** model it as a parser differential and read [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md)
7. **IF** the request skips the filter by changing the HTTP verb **THEN** route to [`http-method-and-verb-attacks`](../http-method-and-verb-attacks/SKILL.md) for verb-complete enforcement
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every path variant returns the same login redirect as the canonical protected path **THEN** STOP and record a verified non-finding rather than reporting a routing quirk as a bypass

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Reached endpoint is an admin function, not an unauthenticated area | [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) | Invariant is function-level authorization, not a skipped auth filter |
| Trick works because proxy and origin normalise URLs differently | [`web-cache-poisoning-and-deception-deception-and-path`](../web-cache-poisoning-and-deception-deception-and-path/SKILL.md) | Invariant is parser-differential path handling across tiers |
| Filter is skipped by changing the HTTP verb | [`http-method-and-verb-attacks`](../http-method-and-verb-attacks/SKILL.md) | Invariant is method-complete enforcement across the route |
| Need parent class methodology | [`authentication-bypass`](../authentication-bypass/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the protected routes and the component that guards them.** Determine whether enforcement is a middleware prefix match, a per-handler decorator, a web-server location block, or a WAF rule, and record the exact string form each one compares. The bypass lives in the gap between that form and the routed form.
2. **Capture the canonical baseline.** Request the protected path unauthenticated and record its status, typically a 401 or a redirect to login, plus the response size. Every variant is measured against this.
3. **Generate variants that preserve the route but change the string.** Case folding, trailing slash, dot segments, double slashes, encoded separators such as `%2f`, and appended extensions each test a different normalisation stage. Keep every variant within the authorised target.
4. **Send each variant unauthenticated and compare to the canonical baseline.** A variant that returns protected content, not just a different error, is the signal that the filter and router disagree on that form.
5. **Correlate across tiers where a proxy is present.** Compare the path the edge logged with the path the origin logged for the same request id; a mismatch localises the normalisation disagreement and distinguishes a filter bug from a cache or routing issue.
6. **Stop condition.** Halt when a variant either (a) returns the protected content that the canonical path withholds, (b) returns the same gate response as the canonical path for every form tried, or (c) would require acting on another user's data once inside. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single path variant that unauthenticated returns the protected resource, paired with the canonical path's refusal and the specific normalisation stage that diverged, reproducible across requests. A 200 to a public asset or a redirect loop is not proof.
8. **Close with the structural fix.** Canonicalise the path once and attach authorisation to the resolved route or endpoint rather than to a raw string, apply case-insensitive matching with a closed route set, and default-deny any endpoint without an explicit requirement. Verify by replaying every variant against the hardened gate.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `/Admin` returning 200 where `/admin` returns 401 or a login redirect | Proves case-sensitive filter matching on the stack, a normalisation gap rather than a credential flaw |
| A dot-segment or double-slash variant resolving to the protected handler | Proves the filter reads the raw path while routing uses the canonical form |
| An appended `.json` or alternate extension reaching the same controller | Proves suffix-based evasion on frameworks that strip extensions after the filter runs |
| A proxy-versus-origin path mismatch for one request id in correlated logs | Proves divergent normalisation between tiers, the root of most forced-browsing bypasses |
| A static alias or legacy route serving gated content | Proves an alternate entry point that was never placed behind the filter |
| Direct retrieval of a known object URL with no prior authentication event | Proves the resource trusts obscurity rather than an enforced access check |

## Worked Contrast

**Vulnerable pattern:**

```python
PROTECTED_PREFIX = "/admin"


@app.before_request
def guard():
    # Case-sensitive raw-path prefix match: /Admin and /admin%2f slip past
    if request.path.startswith(PROTECTED_PREFIX):
        if not current_user.is_authenticated:
            abort(401)
```

**Hardened pattern:**

```python
# Authorisation is a property of the resolved route, not of the raw URL string
ROUTE_REQUIREMENTS = {
    "admin_dashboard": "admin",
    "admin_users": "admin",
    "public_home": None,
}


@app.before_request
def guard():
    endpoint = request.url_rule.endpoint if request.url_rule else None
    # Unknown endpoints default to deny, so path tricks that resolve to admin still fail
    requirement = ROUTE_REQUIREMENTS.get(endpoint, "admin")
    if requirement and not current_user.has_role(requirement):
        abort(403)
```

**Why this matters:** The defect gates on the raw request string, so any variant that the router still resolves to the admin handler bypasses a case-sensitive prefix match. The control binds the requirement to the endpoint chosen after routing and default-denies unknown endpoints, so normalisation tricks can no longer separate the check from the handler.

## When It Is NOT This Issue

- **Variant returns the same gate response:** a path variant that still yields the login redirect or 401 is the filter working, not a bypass.
- **Public content behind a pretty URL:** reaching an intentionally public page through an alternate path exposes nothing protected.
- **404 to a non-existent variant:** a variant that simply does not route anywhere is a missing resource, not a skipped gate.
- **Authorisation still enforced at the handler:** a path trick that reaches the handler but is then refused by a per-handler check has met a compensating control.
- **Directory listing disabled already:** an index path that returns 403 with no file enumeration is behaving as configured.
- **Self-owned resource reached directly:** retrieving your own object by its URL without a session is in-scope for that account, not forced browsing to another's data.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authentication-bypass-forced-browsing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authentication-bypass-forced-browsing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authentication-bypass-forced-browsing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`authentication-bypass`](../authentication-bypass/SKILL.md) - Web and Application (core)
- [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-header-and-proxy-trust`](../authentication-bypass-header-and-proxy-trust/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authentication-bypass-forced-browsing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 58 |
| Distinct dataset sources | 15 |
| Top sources | OffsecCyber (24), CYBER_CPT/nuclei_templates (6), ctf-solver-dataset (5), hackerone_disclosed_reports (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
