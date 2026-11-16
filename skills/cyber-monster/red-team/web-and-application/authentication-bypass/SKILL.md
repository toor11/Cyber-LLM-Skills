---
name: authentication-bypass
description: Defeats authentication through logic flaws, forced browsing, response manipulation, alternate paths, JWT and header trust, and default or weak credentials. Use when testing login, MFA, SSO or any access gate.
family: web-and-application
tier: core
triggers: ["authentication bypass", "auth bypass", "login bypass", "forced browsing", "auth logic flaw"]
cwe: [CWE-287]
owasp: [A07:2021]
attack: [T1078]
capec: [CAPEC-115]
related: [authentication-bypass-forced-browsing, authentication-bypass-response-manipulation, authentication-bypass-default-and-weak-credentials, sql-injection]
---

# Authentication Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Authentication is the step where the server converts an unauthenticated request into a proven identity, and a bypass is any path that reaches authenticated state without completing that proof. The defect lives wherever the gate is assumed rather than enforced: a route that was never placed behind the filter, a JWT whose payload is decoded but never cryptographically verified, a login handler that falls through to success on an exception, a multi-step flow whose post-factor step is directly postable, or a trust placed in a client-controlled header. The attacker gains a session or token that the credential check should have withheld, and the blast radius is the authority of the identity they land as. Confirmation is always a reachability differential: the same protected resource responds differently to a request that skips the proof versus one that completes it.

- **Precondition chain:** a resource requires a proven identity, a request can reach authenticated state without completing the credential or token proof, and the resulting session or token grants access the unauthenticated caller lacked.
- **Readable differential:** a protected route requested without a valid session or with an unverified token versus the same route with a legitimate session; a bypass exists when the skipped-proof request still returns protected state, and it closes once the gate verifies the proof server-side.
- **Empirical grounding:** CWE-287 Improper Authentication under OWASP Top 10:2025 A07 Authentication Failures; 2025 instances include JWT algorithm confusion in CVE-2025-68925 (Jervis) and the StrongKey FIDO passkey bypass CVE-2025-26788 where a non-discoverable credential flow failed to distinguish discoverable from non-discoverable assertions.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves reaching a protected resource by path or filter tricks **THEN** switch to [`authentication-bypass-forced-browsing`](../authentication-bypass-forced-browsing/SKILL.md) (1 hop)
2. **IF** the target specifically involves flipping a client-side response, status, or flag **THEN** switch to [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) (1 hop)
3. **IF** the target specifically involves vendor default or weak credentials **THEN** switch to [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) (1 hop)
4. **IF** the target specifically involves trust in X-Forwarded-For, X-Original-URL, or internal headers **THEN** switch to [`authentication-bypass-header-and-proxy-trust`](../authentication-bypass-header-and-proxy-trust/SKILL.md) (1 hop)
5. **IF** the credential is a JWT whose signature or algorithm the server does not verify **THEN** treat token verification as the sink and confirm decode-versus-verify before testing other paths
6. **IF** a second factor is enrolled but the session is issued before it is checked **THEN** model it as a multi-step gate skip and post the factor step directly
7. **IF** authentication holds but a session persists after logout or never rotates **THEN** reclassify as a lifecycle problem and read [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every protected route refuses the skipped-proof request and only a valid session succeeds **THEN** STOP and record a verified non-finding rather than forcing a bypass narrative

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Token is a JWT whose signature or alg the server fails to verify | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Invariant is cryptographic token verification, not the login decision |
| A second factor is enrolled but a session issues before it is checked | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | Invariant is step-up completion, a multi-stage state gate |
| Authentication passes but the session never rotates or revokes | [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) | Invariant is credential lifecycle, not initial proof of identity |
| Target matches `authentication-bypass-forced-browsing` | [`authentication-bypass-forced-browsing`](../authentication-bypass-forced-browsing/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `authentication-bypass-response-manipulation` | [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `authentication-bypass-default-and-weak-credentials` | [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `authentication-bypass-header-and-proxy-trust` | [`authentication-bypass-header-and-proxy-trust`](../authentication-bypass-header-and-proxy-trust/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate every gate and how each one is enforced.** List the login endpoint, the token verifier, the session middleware, and each protected route, and record for each whether enforcement is a cryptographic check, a session lookup, or merely an assumption. The bypass is a gate that is assumed, so you must find where proof is claimed but not performed.
2. **Classify the proof model per route.** A route may rely on an ambient session, a bearer JWT, HTTP basic, or a proxy-asserted identity. Each model has a different bypass surface, and mixing them on one route often leaves one unenforced.
3. **Capture a legitimate-session baseline.** Complete the real flow once and record the exact response to the protected resource: status, body shape, and the session or token that unlocked it. This is the proven-identity reference every probe is measured against.
4. **Pick the skip that matches the model.** For session routes, drop or expire the cookie; for JWT routes, substitute a token that is decoded but not validly signed; for multi-step login, post the post-factor step without the factor; for header trust, assert the identity header directly. Change one thing so the result is attributable.
5. **Test verification, not presence.** A hidden token field, a rendered login form, or a client that always sends a header proves nothing; strip or forge the proof and observe whether the server still grants access. Decode-versus-verify is the decisive test for token routes.
6. **Stop condition.** Halt when the skipped-proof request either (a) returns the same protected state as the baseline, confirming the gate is unenforced, (b) is refused identically to an anonymous request, or (c) would require acting on another real user's account to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a protected response obtained by a request that did not complete the credential or token proof, tied to the exact gate that failed to enforce it, and reproducible against the baseline. A 200 on a public shell page, or a token the client happens to send, is not proof of a bypass.
8. **Close with the structural fix.** Verify the token signature with a pinned algorithm, enforce the session or role check on every protected route rather than per page, require the second factor to complete before issuing a session, and never derive identity from a client-settable header. Verify by replaying each skipped-proof probe against the patched gate.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A protected route returning content with no session cookie or bearer token | Proves the authentication filter is not applied to that route on the current stack, independent of the login page |
| `jwt.decode` used in place of `jwt.verify` | Proves the server trusts an unverified token payload on Node, Python, or Go libraries, so forgery is unconstrained |
| A token accepted with its `alg` header set to `none` or swapped to a symmetric algorithm | Proves algorithm confusion on a verifier that does not pin the expected algorithm |
| A session issued after the password stage but before the enrolled second factor | Proves a multi-step gate skip where the post-factor step is directly postable |
| A login endpoint returning success on an exception path or empty credential | Proves a logic fall-through in the credential comparison rather than a cryptographic flaw |
| A protected handler reachable by changing the HTTP verb or appending a path token | Proves enforcement is path- or verb-specific rather than action-complete |
| Vendor firmware shipping a built-in account documented in its manual | Proves a default-credential bypass class common on embedded web panels |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Express middleware: trusts the token payload without verifying the signature
app.use((req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (token) {
    // decode() parses the claims but never checks signature or algorithm
    req.user = jwt.decode(token);
  }
  next();
});
```

**Hardened pattern:**

```javascript
// Verify the signature, pin the algorithm, and reject anything that fails
app.use((req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).end();
  try {
    req.user = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });
  } catch (err) {
    return res.status(401).end();
  }
  next();
});
```

**Why this matters:** Identity is proved by decoding a client-supplied token versus by cryptographically verifying it against a pinned algorithm. The defect lets any attacker mint claims by crafting a payload; the control rejects any token whose signature or algorithm does not match, so the identity is only as trustworthy as the signing key.

## When It Is NOT This Issue

- **Public shell behind the gate:** a 200 on a route that returns only a login prompt or a public skeleton is not a bypass; the protected data must appear.
- **Token the client always sends:** a route that rejects a missing or forged token is enforced even if the front end currently always attaches one; test by stripping the proof.
- **Expired-session grace window:** a brief acceptance of a just-expired session by design is a lifecycle tuning question, not an authentication bypass.
- **Self-registered access:** reaching a feature that self-service signup already grants is in-scope for that account, not a bypass of the gate.
- **Rate-limited login that still verifies:** a slow or throttled login that nonetheless checks the credential correctly is a hardening topic, not CWE-287.
- **Read-only probe against a demo tenant:** access to a sandbox account seeded for testing is a test-environment artefact, not proof of a production bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authentication-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authentication-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authentication-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`authentication-bypass-forced-browsing`](../authentication-bypass-forced-browsing/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authentication-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 63 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (32), securecode-web (20), CYBER_CPT/nuclei_templates (8), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 8 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
