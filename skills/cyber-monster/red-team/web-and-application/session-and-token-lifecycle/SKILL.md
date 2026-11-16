---
name: session-and-token-lifecycle
description: "Tests session handling weaknesses: fixation, predictable identifiers, missing rotation, weak expiry, revocation gaps, cookie attribute mistakes and concurrent session abuse. Use when reviewing how sessions are issued, stored and invalidated."
family: web-and-application
tier: leaf
triggers: ["session management", "session fixation", "session hijack", "cookie attributes", "session expiry", "token lifecycle"]
cwe: [CWE-384, CWE-613]
owasp: [A07:2021]
attack: []
capec: [CAPEC-60]
related: [session-and-token-lifecycle-fixation-and-prediction, session-and-token-lifecycle-cookie-attribute-flaws, session-and-token-lifecycle-revocation-gaps, sql-injection]
---

# Session and Token Lifecycle - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A session or token lets a user skip re-authentication, so its security depends on lifecycle rather than byte format: how the identifier is issued, bound, rotated, and invalidated. The server must be able to invalidate a session server-side on logout, password change, and privilege change; the cookie attributes Secure, HttpOnly, SameSite, Domain, and Path must bind the identifier to one origin and transport; and rotation at privilege boundaries must be enforced with reuse of a rotated value detected. The decision point is the server-side session store and the Set-Cookie attributes, not any signature inside a token. An attacker gains persistent access by fixing, predicting, stealing, or replaying an identifier the server still honours.

- **Precondition chain:** authentication state is carried by a session identifier or token, at least one of server-side invalidation, origin and transport binding via cookie attributes, or rotation with reuse detection is missing, and an attacker can obtain or set an identifier the server continues to accept.
- **Readable differential:** an identifier used before a lifecycle event such as logout, rotation, or password change versus the same identifier used after it; the finding is that the post-event request still authenticates, and it reverts once the server invalidates the identifier on that event.
- **Empirical grounding:** CWE-384 (session fixation) and CWE-613 (insufficient session expiration) anchor this class under OWASP Top 10:2025 A07:2025 Authentication Failures.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target involves forcing or predicting the identifier **THEN** switch to [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) (1 hop)
2. **IF** the target involves Secure, HttpOnly, SameSite, Domain, or Path attributes **THEN** switch to [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) (1 hop)
3. **IF** the target involves logout, password change, or token reuse after revocation **THEN** switch to [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) (1 hop)
4. **IF** the credential is a self-contained signed token whose claims are the concern **THEN** that is a token-format invariant; see [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
5. **IF** the identifier is readable by client script and exfiltration is the worry **THEN** storage is distinct from lifecycle; see [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md)
6. **IF** cross-site requests ride the ambient session **THEN** the forgeability is a request-authenticity invariant; see [`csrf`](../csrf/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the server invalidates server-side, binds via cookie attributes, and rotates with reuse detection **THEN** STOP and classify as a verified non-finding for CWE-384 and CWE-613

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The credential is a stateless signed token | [`jwt-attacks`](../jwt-attacks/SKILL.md) | Verification shifts to algorithm and key handling; lifecycle cannot revoke a stateless token without a store |
| The identifier is stolen from browser storage | [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md) | Theft via script or localStorage is a storage invariant, not issuance or revocation |
| An ambient cookie drives a cross-site state change | [`csrf`](../csrf/SKILL.md) | Forgeability depends on SameSite and token checks, a request-authenticity invariant |
| Target matches `session-and-token-lifecycle-fixation-and-prediction` | [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `session-and-token-lifecycle-cookie-attribute-flaws` | [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `session-and-token-lifecycle-revocation-gaps` | [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory where authentication state lives.** Determine whether the server keeps a session record it can delete or trusts a self-contained token it cannot, and capture the Set-Cookie attributes issued at login.
2. **Classify the three lifecycle controls independently.** Establish server-side invalidation capability, cookie binding through Secure, HttpOnly, SameSite, Domain, and Path, and rotation with reuse detection, because each is a separate decision point.
3. **Baseline an authenticated identifier.** With a disposable test account, record a working session identifier and the exact requests it authorises.
4. **Define the baseline-versus-probe differential per control.** Compare the identifier accepted before and after a lifecycle event, and compare a pre-rotation value reused after rotation.
5. **Decide the branch from what the store shows.** If logout leaves the record live, the revocation branch is the finding; if the cookie lacks binding attributes, the attribute branch is; if a rotated value still works, the rotation branch is; route to the matching child skill for depth.
6. **Stop condition.** Stop when (a) an identifier the server should have invalidated still authenticates after its lifecycle event, (b) every post-event request is rejected, or (c) advancing requires using another real user's live session. Case (a) confirms a lifecycle gap, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a post-event request that still authenticates on the victim-equivalent account, with the lifecycle event and the surviving identifier shown side by side, plus the store or configuration line that fails to invalidate. A 200 to an unrelated public page is not proof.
8. **Close with the structural fix.** Keep a server-side session record keyed to a rotating identifier, delete it on logout, password change, and privilege change, set Secure, HttpOnly, and SameSite, scope Domain and Path tightly, and detect reuse of a rotated identifier; verify by replaying each post-event probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A session identifier accepted after the server returned a logout response | Proves revocation is client-side only with no server-side record deletion; stateful session backends |
| A Set-Cookie for the session omitting Secure, HttpOnly, or SameSite | Proves the cookie is not bound to one transport or origin, widening theft and forgery on any cookie-based session |
| The same identifier valid before and after a password change | Proves lifecycle events do not propagate to active sessions; account-management flows |
| A pre-rotation identifier still honoured after login rotated it | Proves rotation without reuse detection, the fixation-adjacent lifecycle gap; login handlers |
| A Domain scoped to a parent domain shared with untrusted subdomains | Proves over-broad cookie scope enabling cross-subdomain reuse; multi-subdomain hosts |
| A stateless token honoured after the user logged out | Proves there is no revocation list for a self-contained credential; JWT-style sessions without a denylist |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.post("/login")
def login():
    user = authenticate(request.form["user"], request.form["password"])
    # Reuses whatever session id the client already had and keeps it after login;
    # logout only clears the client cookie, so the server never invalidates it.
    session["uid"] = user.id
    return redirect("/dashboard")

@app.post("/logout")
def logout():
    resp = redirect("/")
    resp.delete_cookie("session")
    return resp
```

**Hardened pattern:**

```python
@app.post("/login")
def login():
    user = authenticate(request.form["user"], request.form["password"])
    old = request.cookies.get("session")
    if old:
        server_sessions.revoke(old)          # kill any attacker-fixed id
    sid = server_sessions.create(user.id)    # fresh, random, server-side record
    resp = redirect("/dashboard")
    resp.set_cookie("session", sid, secure=True, httponly=True, samesite="Lax")
    return resp

@app.post("/logout")
def logout():
    server_sessions.revoke(request.cookies.get("session"))   # server-side invalidation
    resp = redirect("/")
    resp.delete_cookie("session")
    return resp
```

**Why this matters:** The hardened login revokes any pre-existing identifier, mints a fresh server-side session record, and sets Secure, HttpOnly, and SameSite so the cookie is bound to one transport and origin; logout deletes the server record rather than only the client cookie. Invalidation and rotation now happen in the store, which a client-side clear can never guarantee.

## When It Is NOT This Issue

- **Logout clears only the client cookie by design on a stateless API:** if the architecture is explicitly stateless with short expiry plus a denylist, surviving a client clear is expected and the finding is whether a denylist exists.
- **Idle timeout not yet elapsed:** a session still valid within its documented lifetime is not an expiration flaw.
- **Self-only reuse:** replaying your own identifier on your own account proves nothing without a cross-user or post-revocation angle.
- **Remember-me token by design:** a long-lived persistent token the server can still revoke is a feature, not CWE-613, unless revocation fails.
- **New identifier issued while the old one simply expires later:** rotation that invalidates the old value immediately is correct even if the old value lingers in logs.
- **Cookie attributes set by a downstream proxy:** if an edge layer adds Secure or HttpOnly, their absence in the application response is cosmetic, so verify the client-received Set-Cookie.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `session-and-token-lifecycle` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `session-and-token-lifecycle` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: session-and-token-lifecycle
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-384, CWE-613 | Mapping: A07:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `session-and-token-lifecycle` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-384, CWE-613`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 50 |
| Distinct dataset sources | 8 |
| Top sources | securecode-web (20), OffsecCyber (14), SecEval/owasp_wstg (5), ctf-solver-dataset (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
