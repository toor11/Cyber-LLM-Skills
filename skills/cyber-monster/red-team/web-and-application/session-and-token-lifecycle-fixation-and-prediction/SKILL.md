---
name: session-and-token-lifecycle-fixation-and-prediction
description: Session fixation and identifier prediction. Covers forcing a known session identifier, accepting identifiers from URL or body, and predicting sequential or timestamp-based identifiers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["session fixation", "predictable session", "session id prediction"]
cwe: [CWE-384, CWE-613]
owasp: [A07:2021]
attack: []
capec: [CAPEC-60]
related: [session-and-token-lifecycle, session-and-token-lifecycle-cookie-attribute-flaws, session-and-token-lifecycle-revocation-gaps, sql-injection]
parent: session-and-token-lifecycle
---

# Session and Token Lifecycle Fixation and Prediction - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Fixation and prediction attack the issuance half of the lifecycle. Fixation works when the application accepts a session identifier supplied by the attacker through a URL parameter, a body field, or a pre-set cookie and keeps using it across the login boundary, so the victim authenticates into an identifier the attacker already knows. Prediction works when identifiers are generated from a sequential counter, a timestamp, or a weak pseudo-random generator, so an attacker can compute a valid live identifier without observing it. The decision point is whether login mints a fresh high-entropy identifier and rejects externally supplied ones. The attacker gains an authenticated session without ever stealing a cookie.

- **Precondition chain:** the application either honours an externally supplied session identifier across login or derives identifiers from guessable material, login does not rotate to a fresh random identifier, and the attacker can plant or compute an identifier the victim's authentication binds to.
- **Readable differential:** a session identifier the attacker set or predicted before login versus the identifier present after login; the finding is that they are identical for fixation or computable for prediction, and it reverts when login issues a fresh unpredictable identifier and discards the supplied one.
- **Empirical grounding:** CWE-384 (session fixation) and CWE-613 under OWASP Top 10:2025 A07:2025 Authentication Failures anchor identifier planting and predictable-identifier generation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as fixation or prediction **THEN** start at parent class [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) first
2. **IF** the identifier can be supplied via a URL or body parameter **THEN** test whether the application accepts and keeps it across login, the classic fixation case
3. **IF** a pre-set cookie survives the login boundary **THEN** confirm the post-login identifier equals the pre-set one before reporting
4. **IF** identifiers look sequential or timestamp-derived **THEN** collect a sample and test predictability rather than assuming randomness
5. **IF** identifiers are short or low-entropy **THEN** estimate the keyspace, since a guessable identifier is a prediction finding
6. **IF** the concern is reuse after logout rather than issuance **THEN** switch to [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) (1 hop)
7. **IF** the identifier is set-able because an upstream authentication step is skippable **THEN** assess [`authentication-bypass`](../authentication-bypass/SKILL.md) separately
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** login mints a fresh high-entropy identifier and rejects supplied ones **THEN** STOP and classify as a verified non-finding for CWE-384

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A guessable identifier is really a predictable reset or one-time code | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | Predictable one-time codes are a rate-limit and entropy invariant on a different flow |
| The identifier can be planted because a pre-auth page sets it | [`authentication-bypass`](../authentication-bypass/SKILL.md) | Skippable authentication is an access-control invariant rather than identifier entropy |
| A fixed identifier is delivered via a cross-site request | [`csrf`](../csrf/SKILL.md) | Planting a cookie cross-site is a request-authenticity vector feeding fixation |
| Need parent class methodology | [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate identifier issuance and acceptance.** Find where the session identifier is generated at login and every place the application reads an incoming identifier, whether cookie, URL parameter, or hidden field.
2. **Classify the opportunity.** Decide whether the risk is fixation, an external identifier honoured across login, or prediction, identifiers derived from guessable material, because the two need different probes.
3. **Baseline the pre-login identifier.** As an unauthenticated client, record the identifier the application assigns or accepts, including any value you can set yourself.
4. **Define the baseline-versus-probe differential.** For fixation, log in and compare the post-login identifier against the pre-login one; for prediction, collect a timed sample of issued identifiers and test for sequence or timestamp structure.
5. **Branch on the evidence.** If the post-login identifier equals the planted one, fixation is confirmed; if sampled identifiers are monotonic or clock-correlated, prediction is the finding; do not conflate them.
6. **Stop condition.** Stop when (a) a planted identifier survives login or a sampled identifier is computable, (b) login always rotates to an unrelated high-entropy value, or (c) advancing requires hijacking a real user's authenticated session. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the pre-login and post-login identifier being identical for fixation or a demonstrated generator pattern across a sample for prediction, plus the issuance line that fails to rotate or uses weak entropy. A single observed identifier is not a predictability proof.
8. **Close with the structural fix.** Generate identifiers from a cryptographically secure generator with adequate length, reject any identifier not minted server-side, and rotate to a fresh value at every authentication and privilege change; verify by replaying the plant and the sampling probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| The post-login session identifier equal to one set before authentication | Proves session fixation because login did not rotate; frameworks that reuse the pre-authentication session |
| A session identifier accepted from a URL or request-body parameter | Proves the application honours externally supplied identifiers, the fixation entry point; URL-rewriting session handlers |
| Issued identifiers increasing monotonically across requests | Proves a sequential generator that is directly predictable; counter-based session stores |
| Identifiers correlating with issue time or process id | Proves timestamp or weak pseudo-random derivation; custom token generators seeded from the clock |
| Identifier length or alphabet too small to resist enumeration | Proves an insufficient keyspace for a live session; short numeric session tokens |
| The login response reusing the same Set-Cookie value seen pre-authentication | Proves no rotation at the authentication boundary, the fixation-specific lifecycle gap |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.post("/login")
def login():
    # Honours a session id from the query string and keeps it after login, so
    # an attacker who plants a known sid fixes the victim's session.
    sid = request.args.get("sid") or session.get("sid") or make_id()
    if authenticate(request.form["user"], request.form["password"]):
        session["sid"] = sid
        session["auth"] = True
    return redirect("/home")
```

**Hardened pattern:**

```python
import secrets

@app.post("/login")
def login():
    if not authenticate(request.form["user"], request.form["password"]):
        return redirect("/login")
    # Ignore any supplied identifier and mint a fresh high-entropy value on login.
    new_sid = secrets.token_urlsafe(32)
    server_sessions.rotate(request.cookies.get("session"), new_sid)
    resp = redirect("/home")
    resp.set_cookie("session", new_sid, secure=True, httponly=True, samesite="Lax")
    return resp
```

**Why this matters:** The hardened login discards any attacker-supplied identifier, generates a fresh value from a cryptographically secure generator, and rotates the server-side record at the authentication boundary. Fixation fails because the post-login identifier is unrelated to any planted value, and prediction fails because the keyspace is cryptographically large.

## When It Is NOT This Issue

- **Identifier changes at login but the old value lingers in a log:** rotation that issues a new identifier is correct even if the pre-authentication value appears in history.
- **Supplied identifier ignored:** an application that accepts a sid in the URL but overwrites it at login is not fixable, so confirm the post-login value differs.
- **Framework identifier that looks sequential but is signed:** an index inside a signed, random-keyed token is not predictable without the key.
- **Short identifier backed by a server-side entropy map:** a short opaque handle mapped to a random server record is not brute-forceable if the lookup is unguessable and rate-limited.
- **Self-planted identifier on your own browser:** fixing your own session proves nothing without a second victim principal.
- **Pre-authentication session for a CSRF token only:** a pre-login session holding only a CSRF token and replaced at login is expected.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `session-and-token-lifecycle-fixation-and-prediction` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `session-and-token-lifecycle-fixation-and-prediction` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: session-and-token-lifecycle-fixation-and-prediction
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-384, CWE-613 | Mapping: A07:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-cookie-attribute-flaws`](../session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `session-and-token-lifecycle-fixation-and-prediction` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-384, CWE-613`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 9 |
| Top sources | hackerone_disclosed_reports (5), OffsecCyber (4), ctf-solver-dataset (4), CYBER_CPT/expku (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
