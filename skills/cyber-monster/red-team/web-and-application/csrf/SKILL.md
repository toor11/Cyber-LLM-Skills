---
name: csrf
description: Tests cross-site request forgery including missing or weak anti-CSRF tokens, SameSite misconfiguration, JSON and multipart edge cases, login CSRF, and token-leak paths. Use when a state-changing request relies on ambient cookies for authentication.
family: web-and-application
tier: core
triggers: ["csrf", "cross-site request forgery", "anti-csrf", "samesite", "xsf", "request forgery"]
cwe: [CWE-352]
owasp: [A01:2021]
attack: [T1185]
capec: [CAPEC-62]
related: [sql-injection, cross-site-scripting, ssrf, path-traversal-and-lfi]
---

# CSRF - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)

## Mechanism and Preconditions

The browser attaches ambient credentials to any request the page causes, so an attacker's page can trigger a state-changing request the victim never intended. The server cannot distinguish that request from a legitimate one unless it verifies something the attacker's page cannot read or set. Three independent checks can supply that proof: a token bound to the session and compared server-side, an `Origin`/`Referer` decision, and a cookie `SameSite` policy that withholds the cookie on cross-site requests. The technique is about finding which of those three is absent or bypassable for a specific state-changing route, and whether the resulting change is consequential.

- **Precondition chain:** a state-changing route authenticates solely from an ambient credential, the attacker can predict the full request shape (method, path, parameters), and no check ties the request to the victim's own session.
- **Readable differential:** the same state change issued from a cross-site context versus a same-site context; the cross-site attempt must succeed for a finding, and must be rejected once a token or Origin check is enforced.
- **Empirical grounding:** CWE-352 covers this class; OWASP Top 10:2025 places CSRF under A01:2025 Broken Access Control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the route changes state and accepts a cookie-authenticated POST from anywhere **THEN** this is the primary case; establish the cross-site differential before anything else
2. **IF** the route is authenticated but the cookie is `SameSite=Lax` and the action is reachable by top-level GET **THEN** treat it as a live finding; lax does not protect top-level navigation, so confirm whether any state change rides on GET
3. **IF** the cookie is `SameSite=None` without `Secure`, or the browser default is relied on **THEN** record the cookie attributes as the finding surface and check whether the framework sets a token independently
4. **IF** the form posts JSON and a token header is expected but not enforced **THEN** test token absence and token reuse separately; a client that sends a token does not prove the server validates it
5. **IF** the token is present but accepted across sessions or after rotation **THEN** this is a token-binding failure, which is still CWE-352; confirm with two accounts before reporting
6. **IF** the action is a login or logout endpoint **THEN** assess login CSRF and logout CSRF as their own impact stories rather than reusing the standard form-CSRF narrative
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)
8. **IF** the credential is a bearer token sent from script rather than an ambient cookie **THEN** STOP and classify as a verified non-finding for CWE-352; that is a token-storage or XSS question, not request forgery

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Token absent entirely on a state-changing route | [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Remediation is framework token middleware plus an Origin decision |
| Token present but not bound to the session | [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) | The failure is token lifecycle, not token presence |
| Cross-site scripting already present | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | With script execution the anti-CSRF token can be read, so the CSRF finding is usually subsumed |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate state-changing routes, not pages.** List every method and path that mutates account state: email change, password change, MFA enrolment, API key creation, role grant, payment instrument change. A route that only reads is out of scope for this skill even when it is cookie-authenticated.
2. **Determine the credential model for each route.** Ambient cookie, header bearer token, HTTP basic, or mTLS. Only the ambient models are candidates; the others require script access and therefore a different finding.
3. **Read the enforcement, not the form.** Confirm server-side whether a token is compared, whether `Origin` or `Referer` is consulted, and what `SameSite` value the session cookie actually carries. A hidden token field in the HTML proves nothing about enforcement.
4. **Record a same-site baseline.** Perform the state change from the same origin and capture the exact request: method, path, content type, parameter names, and required headers. This is the request shape an attacker must reproduce.
5. **Apply the cross-site differential.** Reproduce that exact shape from a different origin. If the server accepts it, the invariant is missing. If it rejects it, identify which of the three checks rejected it, because the other two may still be absent and the conclusion changes.
6. **Test the weakest link separately.** Token absence, token reuse after rotation, token accepted from another session, and `Origin` present-but-unchecked are four distinct failures. Test one at a time so the report names the actual broken control.
7. **Stop condition.** Stop when the cross-site request either succeeds and changes state, is blocked by a control you can name, or would require reading or altering another real user's data. The first is confirmation, the second is a non-finding, the third is out of scope.
8. **State what counts as proof.** Proof is a request that originates from a foreign origin and still mutates the victim's account, evidenced by the pre/post state difference on the victim's own session, plus the exact missing check. A 200 response with no state change is not proof.
9. **Close with the structural fix.** Bind a per-session token and compare it server-side on every unsafe method, add an `Origin`/`Referer` decision as defence in depth, set `SameSite=Lax` or `Strict` on session cookies, and never allow a state change on GET. Verify by replaying the cross-site attempt.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| State-changing route with no token in the request and no `Origin` check in the handler | Proves the request is forgeable on any cookie-authenticated framework; the absence of a server-side comparison is the finding, not the absence of a form field |
| Session cookie issued without `SameSite`, relying on browser defaults | Proves the protection is browser-dependent on Chrome, Safari, and Firefox with different defaults; a cross-site POST may still carry the cookie on some clients |
| `SameSite=Lax` combined with a state change reachable by top-level GET | Proves a live path because lax cookies are sent on top-level navigation; common in frameworks that allow GET handlers to mutate |
| Token value identical across two sessions or unchanged after login | Proves the token is not bound to the session, so an attacker who obtains any token can forge; affects custom implementations more than framework defaults |
| `Origin` header read but compared with a substring or suffix test | Proves an allowlist bypass of the secondary check on any stack that hand-rolls the comparison |
| JSON content type accepted without a preflight-triggering custom header | Proves the content-type assumption is wrong: a form-encoded or text/plain body may be accepted by the same handler |
| Login endpoint that sets a session without any CSRF consideration | Proves login CSRF, where the victim is signed into the attacker's account and subsequent activity is captured |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Session cookie + no request-origin check: any site can post this form
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { sameSite: "none" } }));

app.post("/account/email", (req, res) => {
  db.users.update(req.session.userId, { email: req.body.email });
  res.json({ ok: true });
});
```

**Hardened pattern:**

```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { sameSite: "lax", secure: true, httpOnly: true },
}));

// Token bound to the session, compared before any mutation
app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const sent = req.get("x-csrf-token") || req.body?._csrf;
  if (!sent || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(req.session.csrf))) {
    return res.status(403).json({ error: "csrf token missing or invalid" });
  }
  next();
});

app.post("/account/email", (req, res) => {
  db.users.update(req.session.userId, { email: req.body.email });
  res.json({ ok: true });
});
```

**Why this matters:** The hardened version keeps the cookie off cross-site requests with `SameSite=Lax`, requires an unguessable token tied to the server-side session, and compares it in constant time before the mutation. The token is the primary control; `SameSite` and an Origin decision are defence in depth.

## When It Is NOT This Issue

- **Self-only state change:** a forged request that alters only the attacker's own session is not a finding. The impact requires the victim's session to change.
- **Token enforced but not sent by the client:** a route that rejects a missing token is protected even if the front-end currently always sends one. Test by removing the token rather than by reading the JavaScript.
- **Bearer token in an `Authorization` header:** a cross-site page cannot set that header without a preflight the server refuses, so the route is not CSRF-prone regardless of cookie configuration.
- **`SameSite=Strict` cookie on the only session credential:** cross-site requests carry no credential, so the request is anonymous and the action has no victim context.
- **`Origin` rejection observed:** if the server refuses a foreign `Origin` for the exact route, the finding is closed even when no token exists. Record the check as the compensating control.
- **State change that already requires re-authentication:** a route that prompts for the current password or a fresh MFA challenge before mutating is not forgeable end to end.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `csrf` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `csrf` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: csrf
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-352 | Mapping: T1185]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)
- [`file-upload-and-webshell`](../file-upload-and-webshell/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `csrf` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-352, T1185`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 70 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (30), securecode-web (18), CYBER_CPT/nuclei_templates (7), cyber-security/security-code (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 8 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
