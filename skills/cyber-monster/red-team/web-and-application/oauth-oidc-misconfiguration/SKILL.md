---
name: oauth-oidc-misconfiguration
description: "Exploits OAuth 2.0 and OpenID Connect flows: redirect URI matching flaws, missing state, code and token leakage, PKCE downgrade, scope escalation, implicit-flow abuse and account-linking attacks. Use when reviewing third-party or social login."
family: web-and-application
tier: core
triggers: ["oauth", "oidc", "openid connect", "redirect_uri", "authorization code", "implicit flow", "pkce"]
cwe: [CWE-601, CWE-287]
owasp: [A07:2021]
attack: [T1550]
capec: [CAPEC-657]
related: [oauth-oidc-misconfiguration-redirect-uri-abuse, oauth-oidc-misconfiguration-flow-and-state-flaws, oauth-oidc-misconfiguration-token-and-scope-abuse, sql-injection]
---

# Oauth OIDC Misconfiguration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

An OAuth 2.0 and OpenID Connect deployment splits trust across the authorization server, the client (relying party), and the browser that ferries parameters between them, and the misconfiguration is any point where one party trusts a value it should have validated. The authorization endpoint returns a code or token keyed to client_id, redirect_uri, scope, state, and (for OIDC) nonce; if redirect URIs are matched loosely, if state or nonce are missing or reused, if PKCE is absent or downgradable, or if the token's audience, issuer, or scope are not checked, an attacker can capture a code, fix a session, swap a token, or escalate scope. The gain is account takeover or access beyond consent. Confirmation is a flow completed with a tampered parameter that still yields a usable code, token, or session, reverting when the omitted check is enforced.

- **Precondition chain:** An OAuth or OIDC flow issues credentials bound to request parameters, at least one of exact redirect matching, state or nonce, PKCE S256, or audience/issuer/scope validation is absent or bypassable, and the attacker can influence that parameter or intercept the resulting credential.
- **Readable differential:** A normal flow versus one with a tampered redirect_uri, omitted state, stripped PKCE, or swapped token; a finding exists when the tampered flow still authenticates or authorises, and it closes once the corresponding check is enforced per RFC 9700.
- **Empirical grounding:** CWE-601 and CWE-287; RFC 9700 (OAuth 2.0 Security Best Current Practice, BCP 240, January 2025) is the baseline, requiring exact redirect URI matching, PKCE with S256, rejecting a code_verifier when no code_challenge was sent, nonce or one-time state, and no open redirectors.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the flaw is in how the redirect_uri is matched or chained **THEN** switch to [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) (1 hop)
2. **IF** the flaw is a missing or reused state, a PKCE downgrade, or a provider mix-up **THEN** switch to [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) (1 hop)
3. **IF** the flaw is scope escalation, token substitution, or audience validation **THEN** switch to [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) (1 hop)
4. **IF** the id_token or access token is a JWT whose signature or alg is in question **THEN** pivot to [`jwt-attacks`](../jwt-attacks/SKILL.md) because the invariant is token integrity, not flow configuration
5. **IF** the final redirect is a generic open redirector reachable outside OAuth **THEN** pivot to [`open-redirect`](../open-redirect/SKILL.md) because RFC 9700 forbids open redirectors in the flow
6. **IF** sign-in links a social identity to an existing local account without verification **THEN** assess account-linking takeover as its own impact story with two controlled accounts
7. **IF** the provider is SAML rather than OAuth or OIDC **THEN** pivot to [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) for the assertion-signature invariant
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
9. **IF** redirect matching is exact, state and nonce are one-time, PKCE S256 is enforced, and token audience, issuer, and scope are validated with no tamperable gap **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The token is a JWT with a signature or alg weakness | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Invariant is token signature integrity, not flow parameter validation |
| The flow ends at a generic open redirector | [`open-redirect`](../open-redirect/SKILL.md) | Invariant is redirect destination control, which RFC 9700 bans in the flow |
| Login federates via SAML assertions | [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) | Invariant is XML assertion signing, a different federation protocol |
| Target matches `oauth-oidc-misconfiguration-redirect-uri-abuse` | [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `oauth-oidc-misconfiguration-flow-and-state-flaws` | [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `oauth-oidc-misconfiguration-token-and-scope-abuse` | [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the flow and the three parties.** Capture the full authorization request and the token exchange, and record which grant is in use (authorization code, code plus PKCE, implicit, or hybrid) because the required checks differ by grant.
2. **Inventory the parameters under test.** List client_id, redirect_uri, scope, state, nonce, code_challenge and its method, and response_type, and note for each whether the server appears to validate it.
3. **Record a clean baseline flow.** Complete a normal login with a controlled account and capture the issued code, the token claims (iss, aud, scope, nonce), and the resulting session as the reference.
4. **Choose the branch from the observed gap.** Loose redirect matching routes to redirect-uri abuse; missing state or nonce or strippable PKCE routes to flow-and-state; unchecked audience or scope or reusable tokens routes to token-and-scope; pick the one the baseline exposes.
5. **Apply one tampered parameter against the baseline.** Alter a single value, a redirect suffix, an omitted state, a removed code_challenge with a submitted verifier, or a widened scope, and compare the outcome to the clean flow.
6. **Stop condition.** Halt when the tampered flow either (a) still yields a usable code, token, or session and reverts when the check is enforced, (b) is rejected identically to a genuinely invalid request, or (c) would require capturing a real user's live code or token. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a flow that authenticates or authorises with a parameter the spec says must be validated, evidenced by an issued credential or a crossed-account session tied to that one change, plus the missing RFC 9700 control. A 302 to an allowed URI is not proof.
8. **Isolate which single control is broken.** Redirect exactness, state or nonce one-time use, PKCE S256 enforcement, and audience, issuer, and scope validation are independent, so name the one that failed.
9. **Close with the structural fix.** Enforce exact redirect URI matching, bind and single-use state and nonce, require PKCE S256 and reject a verifier when no challenge was sent, and validate token issuer, audience, and scope server-side, then replay the tampered flow to confirm it is now rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An authorization request whose redirect_uri is accepted with an extra path or subdomain | Proves loose redirect matching at the authorization server, the entry point for code theft |
| A flow that completes with no state parameter or a static one | Proves missing CSRF and one-time binding on the callback, enabling login CSRF or code injection |
| A token exchange accepted with a code_verifier but no prior code_challenge | Proves a PKCE downgrade the authorization server failed to reject, contrary to RFC 9700 |
| An access token accepted by a resource server without an audience check | Proves token substitution across clients where aud is not validated |
| An id_token consumed without verifying nonce against the session | Proves replay exposure in the OIDC client, independent of signature validity |
| A consent screen granting a broader scope than the client requested | Proves scope escalation in the authorization server's grant logic |
| A social login that links to a local account by email without verification | Proves an account-linking takeover path in the relying party |

## Worked Contrast

**Vulnerable pattern:**

```python
def oauth_callback(request, session):
    code = request.args["code"]
    # No state check and the redirect target comes from the request
    token = exchange_code(code)
    session["user"] = userinfo(token)
    return redirect(request.args.get("next", "/"))
```

**Hardened pattern:**

```python
import hmac

REGISTERED_REDIRECT = "https://app.example/oauth/callback"

def oauth_callback(request, session):
    sent = request.args.get("state", "")
    if not hmac.compare_digest(sent, session.pop("oauth_state", "")):
        abort(400)  # one-time state bound to this session
    token = exchange_code(request.args["code"], redirect_uri=REGISTERED_REDIRECT)
    claims = verify_id_token(token, nonce=session.pop("oauth_nonce", ""))
    session["user"] = claims["sub"]
    return redirect("/")  # fixed internal destination, no open redirector
```

**Why this matters:** The defect accepts a callback with no state check and redirects to a request-controlled next, so an attacker can forge the login and chain an open redirect. The fix compares a one-time state bound to the session, exchanges the code against the exactly registered redirect URI, verifies the id_token nonce, and redirects to a fixed internal path, matching the RFC 9700 baseline.

## When It Is NOT This Issue

- **Allowed redirect used as intended:** a 302 to a correctly registered redirect_uri is the flow working, not an open redirect; impact requires an attacker-controlled destination.
- **State present and validated:** a flow that rejects a missing or altered state is protected even if other hardening is light; record it as the control.
- **Public client with PKCE enforced:** the absence of a client secret is by design for public clients when PKCE S256 is required and enforced.
- **Self-account linking:** linking your own verified social identity to your own account is expected, not a takeover, until it affects another user.
- **Signature-valid token with correct audience:** a token that validates and is scoped to this resource is not a finding merely because it is a bearer token.
- **Test IdP artefacts:** a dev authorization server that accepts loopback redirects is a test configuration unless the production IdP does the same.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `oauth-oidc-misconfiguration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `oauth-oidc-misconfiguration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: oauth-oidc-misconfiguration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601, CWE-287 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) - Web and Application (leaf)
- [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) - Web and Application (leaf)
- [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `oauth-oidc-misconfiguration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601, CWE-287, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 52 |
| Distinct dataset sources | 17 |
| Top sources | OffsecCyber (18), hackerone_disclosed_reports (7), bugbounty-hunter-v1 (5), CYBER_CPT/hacktricks_cloud (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 10 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
