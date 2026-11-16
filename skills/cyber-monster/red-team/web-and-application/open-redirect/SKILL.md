---
name: open-redirect
description: Exploits unvalidated redirects and forwards for phishing, OAuth token theft and SSRF pivoting, including allowlist and parser-differential bypasses. Use when a parameter controls a redirect target, next-URL, return path or host.
family: web-and-application
tier: leaf
triggers: ["open redirect", "url redirect", "redirect bypass", "returnurl", "next parameter", "unvalidated redirect"]
cwe: [CWE-601]
owasp: [A01:2021]
attack: []
capec: [CAPEC-178]
related: [open-redirect-allowlist-bypass, open-redirect-chain-to-token-theft, sql-injection, cross-site-scripting]
---

# Open Redirect - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A request parameter such as next, returnUrl, or redirect_uri carries a destination that the application places into an HTTP 30x Location header or a client-side navigation sink without confirming the destination is one of its own pages. The security decision is destination authority: whether the host the browser ends up on is the application or an attacker site. Because the value is only reflected into navigation, nothing is escaped and no interpreter is involved, so the gap is purely a missing same-site check. The attacker gains a trusted-looking link that bounces a victim off-site for phishing, or an OAuth bounce that carries an authorization code to a foreign origin. Confirmation is a differential in the Location host, not a reflected string or an error.

- **Precondition chain:** A request value reaches a redirect or navigation sink, the application performs no same-site or exact-host check on that value, and the browser actually navigates to the resulting absolute or scheme-relative destination.
- **Readable differential:** The same endpoint with an in-app path versus the same endpoint with an off-site host; a finding exists when the browser navigates off-domain, and it disappears when the value is constrained to a server-side path allowlist.
- **Empirical grounding:** CWE-601 (URL Redirection to Untrusted Site) under OWASP Top 10:2025 A01 Broken Access Control; RFC 9700 (BCP 240, January 2025) requires exact redirect URI matching and forbids open redirectors in OAuth deployments.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves an allowlist that can be defeated by subdomain, userinfo, or encoding tricks **THEN** switch to [`open-redirect-allowlist-bypass`](../open-redirect-allowlist-bypass/SKILL.md) (1 hop)
2. **IF** the redirect is chained into an OAuth or SSO flow to leak a code or token **THEN** switch to [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) (1 hop)
3. **IF** the destination arrives as a scheme-relative `//host` or backslash `/\host` form **THEN** treat it as a parser differential between the server validator and the browser and test both forms
4. **IF** the redirect value is fetched by the server rather than returned to the browser **THEN** reclassify as [`ssrf`](../ssrf/SKILL.md) because the invariant becomes server-side destination validation
5. **IF** the parameter is an OAuth `redirect_uri` validated by prefix or substring **THEN** route to [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) for exact-match registration
6. **IF** the redirect is built client-side through `window.location` or a meta refresh **THEN** confirm server-side headers are irrelevant and test the DOM navigation sink directly
7. **IF** a CRLF sequence in the value splits the response headers **THEN** route to [`crlf-and-header-injection`](../crlf-and-header-injection/SKILL.md) because the defect is header construction, not navigation
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the value only ever resolves to an in-app path and the browser never leaves the origin **THEN** STOP and record a verified non-finding rather than reporting a reflected parameter

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The redirect value is fetched server-side rather than returned to the browser | [`ssrf`](../ssrf/SKILL.md) | The invariant becomes server-side destination validation and resolution, not browser navigation |
| The parameter is an OAuth redirect_uri validated by prefix | [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | The control is exact redirect URI registration, an authorization-server decision |
| A CRLF sequence in the redirect value splits the response headers | [`crlf-and-header-injection`](../crlf-and-header-injection/SKILL.md) | The defect is header-value construction from request data, a different invariant |
| Target matches `open-redirect-allowlist-bypass` | [`open-redirect-allowlist-bypass`](../open-redirect-allowlist-bypass/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `open-redirect-chain-to-token-theft` | [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate every navigation sink and classify it.** Separate server-side 30x Location handlers from client-side `window.location`, `meta refresh`, and framework router redirects. Record for each whole-destination parameters (next, returnUrl, redirect_uri) versus path-only fragments appended to a fixed base.
2. **Choose the branch from how the value is consumed.** If the parameter becomes the Location host, test server-side forms; if a script reads it, test the DOM sink; if it is an OAuth redirect_uri, move to the exact-match question. The consumption point, not a guess, decides which probe set applies.
3. **Record a same-site baseline.** Request the endpoint with a known in-app path and capture the status, the exact Location value, and whether the browser stays on-origin. This is the behaviour an off-site probe must change.
4. **Apply the off-site differential one form at a time.** Compare the in-app path against an absolute `https://` host, a scheme-relative `//host`, a backslash `/\host`, and a `trusted@host` userinfo form. Each isolates a distinct parser gap rather than proving the same thing twice.
5. **Confirm navigation, not header emission.** A Location header alone is not the finding; verify the browser or client actually lands on the foreign host, because some stacks set the header then override it.
6. **Stop condition.** Halt when the probe either (a) sends the browser to an attacker-controlled host and reverts to on-origin once the value is path-constrained, (b) is normalised back to an in-app path for every off-site form, or (c) would require actually phishing a real user to show impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an identical request with one changed destination value producing a Location host or final navigation outside the application origin, plus the handler line that copies the parameter into the redirect without a same-site check. A 302 to an in-app path is not proof.
8. **Close with the structural fix and verify it.** Replace free-form destinations with a server-side allowlist of in-app paths, or map an opaque token to a fixed URL, reject any value carrying a scheme, authority, or leading `//`, and re-run the off-site probe to confirm it now resolves on-origin.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `Location` header whose host is copied verbatim from the `next` parameter | Proves the redirect target is request-controlled on any framework that reflects the parameter into a 30x response |
| A scheme-relative `//host` value accepted where only a path was expected | Proves the parser treats the authority as navigable, a browser-navigation gap on most server routers |
| A backslash `/\host` form normalised to `//host` by the client | Proves a parser differential between the server validator and the browser on Chromium and Firefox |
| A userinfo `https://trusted@evil` form passing a naive host check | Proves the validator read the userinfo segment as the host, a URL-parsing confusion |
| The redirect fires on a plain GET with no further interaction | Proves the navigation is reachable for phishing without any token or POST step on the target |
| A `meta refresh` or `window.location` built from the parameter | Proves a client-side redirect path that server-side header inspection never observes |

## Worked Contrast

**Vulnerable pattern:**

```python
from flask import request, redirect

def go():
    target = request.args.get("next", "/")
    # Any absolute or scheme-relative URL is honoured verbatim
    return redirect(target)
```

**Hardened pattern:**

```python
from urllib.parse import urlsplit
from flask import request, redirect

ALLOWED_PATHS = {"/", "/dashboard", "/account"}

def go():
    target = request.args.get("next", "/")
    parts = urlsplit(target)
    # Reject any scheme, authority, or protocol-relative form; only same-site paths from a closed set
    if parts.scheme or parts.netloc or target.startswith("//") or target not in ALLOWED_PATHS:
        target = "/"
    return redirect(target)
```

**Why this matters:** The hardened version strips the decision down to same-site authority: it rejects anything that carries a scheme or host and then requires membership in a closed path set, so an absolute, scheme-relative, or userinfo destination can never reach the browser.

## When It Is NOT This Issue

- **In-app path only:** the parameter can hold `/dashboard` but any value with a scheme or host is dropped to a default path, so the browser never leaves the origin.
- **Header set then overridden:** a Location header appears in a trace but a later framework hook rewrites it to an on-origin route before the response is sent.
- **Self-referential bounce:** the redirect only cycles the victim between the application's own pages, which carries no phishing or token-leak impact.
- **Signed or opaque token target:** the destination is selected by an unguessable server-side token that maps to a fixed URL, so the caller cannot name an arbitrary host.
- **Email or SMS link preview artefact:** a scanner that pre-fetches links produces a Location hit without any human navigation off-domain.
- **Framework host allowlist already enforced:** the router compares the destination host against a configured allowlist and 400s on mismatch, which is the control working.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `open-redirect` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `open-redirect` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: open-redirect
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`open-redirect-allowlist-bypass`](../open-redirect-allowlist-bypass/SKILL.md) - Web and Application (leaf)
- [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `open-redirect` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 58 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (32), CYBER_CPT/nuclei_templates (14), hackerone_disclosed_reports (11), bug-bounty-pentest-en (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
