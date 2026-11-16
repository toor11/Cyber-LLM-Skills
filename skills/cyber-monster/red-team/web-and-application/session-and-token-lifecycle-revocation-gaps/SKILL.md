---
name: session-and-token-lifecycle-revocation-gaps
description: Session revocation and logout gaps. Covers sessions surviving logout, password change, privilege change and account disable, plus token reuse after revocation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["session revocation", "logout bypass", "session not invalidated", "token reuse"]
cwe: [CWE-384, CWE-613]
owasp: [A07:2021]
attack: []
capec: [CAPEC-60]
related: [session-and-token-lifecycle, session-and-token-lifecycle-fixation-and-prediction, session-and-token-lifecycle-cookie-attribute-flaws, sql-injection]
parent: session-and-token-lifecycle
---

# Session and Token Lifecycle Revocation Gaps - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Revocation gaps are failures in the termination half of the lifecycle. Logout, password change, privilege downgrade, and account disable should each invalidate every active session and refresh token, but if the server only clears the client cookie or trusts a self-contained token with no denylist, a captured or still-held credential keeps working. For stateless tokens the gap is structural: without a server-side revocation list or short expiry plus rotation, there is nothing to invalidate. The decision point is whether a security event propagates to the session store or the token denylist. The attacker gains persistence after the user or an administrator believes access was cut.

- **Precondition chain:** authentication state persists across requests, a security event such as logout, password change, privilege change, or disable does not invalidate the server-side record or add the token to a denylist, and a previously valid credential is still accepted afterwards.
- **Readable differential:** a credential used immediately before a revocation event versus the same credential used immediately after; the finding is that the post-event request still authenticates, and it reverts when the event deletes the server record or denylists the token.
- **Empirical grounding:** CWE-613 (insufficient session expiration) and CWE-384 under OWASP Top 10:2025 A07:2025 Authentication Failures anchor sessions surviving logout, password change, or revocation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as revocation **THEN** start at parent class [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) first
2. **IF** logout returns success but does not delete the server record **THEN** replay the pre-logout credential and confirm it still authenticates
3. **IF** a password change does not terminate other sessions **THEN** test a second, older session after changing the password
4. **IF** a privilege downgrade leaves old sessions at the old level **THEN** verify the cached authorization in a pre-downgrade session
5. **IF** the credential is a stateless signed token **THEN** check for a denylist or short expiry, since without one revocation is structural; see [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
6. **IF** refresh tokens are not rotated or revoked on reuse **THEN** assess refresh reuse with [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) (1 hop)
7. **IF** the account is disabled but sessions persist **THEN** treat surviving sessions after disable as the finding
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every security event invalidates server-side or denylists the token **THEN** STOP and classify as a verified non-finding for CWE-613

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The credential is a stateless signed token with no denylist | [`jwt-attacks`](../jwt-attacks/SKILL.md) | Revoking a self-contained token needs format-aware handling absent from a session store |
| A refresh token is replayed after rotation | [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | Refresh reuse detection is an OAuth grant invariant layered on session revocation |
| A privilege change does not downgrade an active session | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Stale cached authorization is an access-control invariant triggered by the revocation gap |
| Need parent class methodology | [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the security events that must revoke.** List logout, password change, privilege change, and account disable, and locate the handler for each.
2. **Classify the termination mechanism.** Determine whether each event deletes a server-side record, adds a token to a denylist, or merely clears a client cookie, because only the first two actually revoke.
3. **Baseline a working credential.** With a disposable account, capture a credential and confirm the exact authenticated requests it authorises before any event.
4. **Define the baseline-versus-probe differential per event.** Trigger each event, then replay the captured credential and compare acceptance against the pre-event baseline, one event at a time.
5. **Branch on which event fails to propagate.** Logout survival, password-change survival, and disable survival are distinct gaps with distinct fixes, so name which event the store ignored.
6. **Stop condition.** Stop when (a) the captured credential still authenticates after an event that should revoke it, (b) every post-event replay is rejected, or (c) advancing requires using a real user's live credential after their revocation. Case (a) confirms the gap, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a post-event request that authorises the same action as before, with the revocation event and the surviving credential shown together, plus the handler line that does not invalidate or denylist. A cached static asset served post-logout is not proof.
8. **Close with the structural fix.** Delete the server-side session on logout and on password, privilege, and disable events, maintain a token denylist or short expiry plus rotation for stateless credentials, and detect refresh-token reuse; verify by replaying each event's probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A credential accepted after its logout handler returned success | Proves logout clears only the client and never deletes the server record; stateful session applications |
| Older sessions still valid after a password change | Proves the change does not fan out to active sessions; account-security flows without global invalidation |
| A session retaining administrator rights after a role downgrade | Proves cached authorization is not refreshed on privilege change; applications that snapshot roles at login |
| A disabled account's existing session continuing to work | Proves account disable does not revoke live sessions; deprovisioning that only blocks new logins |
| A stateless token honoured with no denylist entry after revocation | Proves there is no revocation mechanism for the token format; JWT sessions lacking a blocklist |
| A rotated refresh token still accepted alongside its successor | Proves missing reuse detection on refresh rotation; OAuth clients without replay guards |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.post("/logout")
def logout():
    # Stateless token session: logout just tells the browser to drop the cookie.
    # The token stays valid until it expires, so a captured copy keeps working.
    resp = make_response(redirect("/"))
    resp.delete_cookie("access_token")
    return resp
```

**Hardened pattern:**

```python
@app.post("/logout")
def logout():
    token = request.cookies.get("access_token")
    claims = decode(token)
    # Record the token id until its natural expiry so it is rejected on reuse.
    denylist.add(claims["jti"], expires_at=claims["exp"])
    server_sessions.revoke_all(claims["sub"])   # also kill sibling sessions
    resp = make_response(redirect("/"))
    resp.delete_cookie("access_token")
    return resp

def is_valid(token):
    claims = decode(token)
    return claims["jti"] not in denylist and not server_sessions.revoked(claims["sub"])
```

**Why this matters:** The hardened logout adds the token's unique id to a denylist that lives until the token's own expiry and revokes the subject's server-side sessions, so a captured copy is rejected on the next request. Revocation becomes an explicit server-side action rather than a client-side cookie deletion the attacker can ignore.

## When It Is NOT This Issue

- **Static assets served after logout:** a content delivery layer returning cached public files post-logout is not session survival, so test an authenticated non-cacheable action.
- **Short-expiry token by design:** a stateless token expiring in a documented small window with rotation is an accepted trade-off, not CWE-613, if reuse is bounded.
- **Logout on one device by design:** per-device logout that intentionally leaves other sessions is a feature, and the finding is whether global invalidation exists where promised.
- **Password change prompting re-login on the same device:** if other devices are also invalidated, the behaviour is correct even if the current device simply re-authenticates.
- **Self-only replay:** replaying your own token after your own logout proves the gap mechanically but needs a cross-user or administrator-revocation angle for impact.
- **Revoked at the gateway, not the application:** if an API gateway denylists the token, the application-level omission is mitigated, so verify where enforcement actually happens.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `session-and-token-lifecycle-revocation-gaps` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `session-and-token-lifecycle-revocation-gaps` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: session-and-token-lifecycle-revocation-gaps
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-384, CWE-613 | Mapping: A07:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `session-and-token-lifecycle-revocation-gaps` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-384, CWE-613`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/osv (4), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
