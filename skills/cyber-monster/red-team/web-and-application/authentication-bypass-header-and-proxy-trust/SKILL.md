---
name: authentication-bypass-header-and-proxy-trust
description: Authentication bypass through header and proxy trust. Covers trust in X-Forwarded-For, X-Original-URL, X-Rewrite-URL and internal-only headers to skip authentication or reach internal routes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["x-original-url", "x-rewrite-url", "header auth bypass", "internal header trust"]
cwe: [CWE-287]
owasp: [A07:2021]
attack: [T1078]
capec: [CAPEC-115]
related: [authentication-bypass, authentication-bypass-forced-browsing, authentication-bypass-response-manipulation, authentication-bypass-default-and-weak-credentials]
parent: authentication-bypass
corpus_sparse: true
---

# Authentication Bypass Header and Proxy Trust - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This variant abuses the application's trust in request headers that only a trusted proxy should ever set. When a backend reads `X-Forwarded-For` to decide a request is internal, honours `X-Original-URL` or `X-Rewrite-URL` to authorise on a path the front proxy never evaluated, or accepts an `X-Internal` or forwarded-identity header as proof of who the caller is, any external client can simply add that header and inherit the privilege. The root cause is that these hop-by-hop or proxy-origin headers are not stripped at the edge, so the trust boundary becomes header presence rather than cryptographic provenance. The attacker gains internal-only routes or an asserted identity without authenticating, and confirmation is a request that flips from a denial to success purely by adding the spoofed header.

- **Precondition chain:** the backend derives a trust or routing decision from a client-settable header, the edge proxy fails to strip or overwrite that header, and no signed assertion or mutual TLS re-establishes provenance behind the proxy.
- **Readable differential:** a protected or internal route requested without the trust header versus the same request with the spoofed header added; a finding exists when only the spoofed request is accepted, and it closes once the edge strips the header and the backend derives trust from a verified source.
- **Empirical grounding:** CWE-287 Improper Authentication expressed as CWE-290 Authentication Bypass by Spoofing and CWE-348 Use of Less Trusted Source; the broader header-provenance class is visible in 2025 host-header injection advisories such as CVE-2025-47424 (Retool) and CVE-2025-36223 (IBM OpenPages, CWE-644), with no leaf-specific CVE so the taxonomy anchors the guidance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match header and proxy trust **THEN** start at parent class [`authentication-bypass`](../authentication-bypass/SKILL.md) (1 hop) for general triage
2. **IF** the backend reads X-Forwarded-For to grant an internal or loopback bypass **THEN** test a spoofed 127.0.0.1 value against the unmodified request
3. **IF** the app honours X-Original-URL or X-Rewrite-URL for authorisation **THEN** check whether the origin authorises on a path the proxy never evaluated
4. **IF** an X-Internal or forwarded role header is accepted from an external client **THEN** confirm whether the edge strips that header before the backend reads it
5. **IF** the trusted header is Host or X-Forwarded-Host feeding links or routing **THEN** route to [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) for host-provenance trust
6. **IF** the injected header reaches a server-side fetch destination **THEN** reclassify as egress control and read [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md)
7. **IF** the forwarded identity header is consumed to authorise an action **THEN** route to [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) because the role must be server-verified
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** adding every candidate trust header changes nothing because the edge overwrites them **THEN** STOP and record a verified non-finding rather than claiming a spoof that the edge neutralises

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Trusted header is Host or X-Forwarded-Host feeding links or routing | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Invariant is host-header provenance, a routing and link-trust gap |
| Injected header reaches a server-side fetch destination | [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) | Invariant becomes egress destination control, not auth trust |
| Forwarded identity header is consumed to authorise an action | [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) | Invariant is server-side authorization regardless of a claimed role header |
| Need parent class methodology | [`authentication-bypass`](../authentication-bypass/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the proxy chain and which headers each hop sets or trusts.** Identify the edge proxy, any internal load balancers, and the application, then determine which of `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, and bespoke internal headers the backend reads. The sink is a trust decision keyed to one of these.
2. **Record a clean baseline.** Request the internal or protected route with no special headers and capture the status, usually 401, 403, or 404. This is the no-trust reference.
3. **Add one trust header at a time.** Set `X-Forwarded-For: 127.0.0.1` to test a loopback bypass, `X-Original-URL` to a privileged path to test proxy-origin authorisation disagreement, and an internal marker such as `X-Internal-Request: true` to test unstripped trust. Changing one header keeps the result attributable.
4. **Distinguish an edge that overwrites from a backend that trusts.** If the header has no effect, confirm whether the edge rewrote it before the backend saw it, because a working control there is not a finding and not evidence of a trusting backend either.
5. **Check the authorisation-versus-routing split for URL-override headers.** Send a benign request line with `X-Original-URL` pointing at the protected path; if the origin authorises on the header path while the proxy gated the request line, the two disagree and the route is reachable.
6. **Stop condition.** Halt when a spoofed header either (a) flips the route from denial to the protected content, (b) is overwritten or ignored for every form tried, or (c) would require pivoting into real internal data to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is a request that succeeds only because a client-settable header was added, measured against the clean baseline, together with the exact header the backend trusted and the fact that the edge did not strip it. A header that the proxy overwrites, or an already-authenticated request, is not proof.
8. **Close with the structural fix.** Strip or overwrite all inbound trust headers at the edge, derive the client address from the correct hop count on the trusted proxy, authorise on the routed path rather than a client-supplied one, and require a signed assertion or mutual TLS for internal trust. Verify by replaying each spoofed header against the hardened edge and backend.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `X-Forwarded-For: 127.0.0.1` flipping an internal-only route to 200 | Proves the app trusts a spoofable client header for a loopback bypass decision on the stack |
| `X-Original-URL` or `X-Rewrite-URL` authorising on a path the proxy did not evaluate | Proves the origin authorises on a rewritten path while the proxy gated the real request line |
| An `X-Internal-Request` or role header honoured from an external client | Proves an internal-trust header was never stripped at the edge |
| `X-Forwarded-Host` steering link generation or routing | Proves host-provenance trust that can redirect flows or poison generated links |
| The auth decision log recording the client IP as loopback for an external request | Proves the forwarded-for hop count is mis-parsed on the current proxy chain |
| Acceptance of a forwarded identity header with no mutual TLS or signed assertion | Proves the trust boundary relies on header presence rather than cryptographic provenance |

## Worked Contrast

**Vulnerable pattern:**

```python
def is_internal(request):
    # Trusts a client-settable header to grant the internal bypass
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() == "127.0.0.1"


def handle(request):
    if is_internal(request) or request.headers.get("X-Internal-Request") == "true":
        return serve_admin(request)  # no authentication performed
    return require_login(request)
```

**Hardened pattern:**

```python
TRUSTED_PROXY_HOPS = 1


def client_ip(request, peer_addr):
    # Only the hop added by our own trusted proxy is authoritative
    chain = [h.strip() for h in request.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
    if not chain or peer_addr not in TRUSTED_PROXIES:
        return peer_addr
    return chain[-TRUSTED_PROXY_HOPS]


def handle(request, peer_addr):
    # Network position never authenticates; require a verified session token
    session = verify_session(request.headers.get("Authorization"))
    if session is None:
        return require_login(request)
    return serve_admin(request, session)
```

**Why this matters:** The defect grants trust from headers any client can set, so a single X-Forwarded-For or X-Internal-Request line bypasses authentication. The control derives the address from the trusted proxy hop, never treats network position as identity, and requires a verified session token, so a spoofed header carries no authority.

## When It Is NOT This Issue

- **Edge overwrites the header:** a proxy that strips or rewrites X-Forwarded-For and friends before the backend reads them has the control in place; the header has no effect and there is no finding.
- **Header reflected but not trusted:** an app that logs X-Forwarded-For for analytics but makes no trust decision from it is not vulnerable.
- **Loopback genuinely required:** a route only reachable from the real loopback interface, not from a spoofed header, is behaving as designed.
- **Signed forwarded identity:** a forwarded-identity header protected by mutual TLS or a signature that the backend verifies carries provenance, not blind trust.
- **Host header used only for logging:** an X-Forwarded-Host echoed in logs but not in links or routing has no exploitable effect.
- **Internal route also behind network policy:** an internal path that a spoofed header reaches at the app but that egress or network policy still blocks is a defect at reduced severity, not a confirmed bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authentication-bypass-header-and-proxy-trust` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authentication-bypass-header-and-proxy-trust` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authentication-bypass-header-and-proxy-trust
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`authentication-bypass`](../authentication-bypass/SKILL.md) - Web and Application (core)
- [`authentication-bypass-forced-browsing`](../authentication-bypass-forced-browsing/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authentication-bypass-header-and-proxy-trust` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
