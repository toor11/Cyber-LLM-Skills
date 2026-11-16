---
name: mfa-and-otp-bypass
description: "Bypasses multi-factor and one-time-password controls: missing server-side checks, response manipulation, code reuse and brute force, backup-code abuse, and rate-limit gaps. Use when testing a second authentication factor."
family: web-and-application
tier: leaf
triggers: ["mfa bypass", "otp bypass", "2fa bypass", "two factor bypass", "mfa", "otp brute force"]
cwe: [CWE-287]
owasp: [A07:2021]
attack: []
capec: [CAPEC-115]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Mfa and Otp Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A second-factor step is meant to be an independent gate: after the password succeeds the server issues a short-lived single-use code (TOTP, SMS or email OTP, a backup code, or a passkey assertion) and must verify it server-side, once, under a strict attempt budget, bound to the same pending-login session. The bypass is a break in one of those properties: a success flag the client controls, a verification endpoint with no rate limit so codes are brute-forced, a code accepted after reuse or outside its window because it is not normalised before the once-per-window check, a backup-code path with weaker checks, or a credential-flow confusion where one factor is validated against a different account. The attacker gains the authenticated session without the factor, shown by a login that completes without a valid current code.

- **Precondition chain:** A password step precedes an independent factor, the verification endpoint lacks one of server-side checking, a per-identity attempt ceiling, single-use plus window invalidation, or session binding, and the attacker can reach that endpoint directly with a victim's pending-login context.
- **Readable differential:** A factor-verification attempt with the correct code versus one with a wrong, reused, or omitted code; a finding exists when the wrong or absent path still yields a session or is not rate-limited, and it closes once the server enforces a single-use, rate-limited, session-bound check.
- **Empirical grounding:** CWE-287 sits under OWASP Top 10:2025 A07:2025 Authentication Failures; anchored by CVE-2025-6015 (Vault, codes not normalised before the once-per-window reuse check, allowing TOTP reuse and rate-limit bypass, fixed 1.20.1), GHSA-57jg-m997-cx3q (Weblate second-factor verification lacked rate limiting, fixed 5.12), CVE-2025-4094 (OTP validation with no rate limit), and CVE-2025-26788 (discoverable and non-discoverable credential flows not distinguished, letting one be used against another account).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the factor is a TOTP or OTP code and the endpoint has no attempt ceiling **THEN** measure the attempt budget first, because an unbounded code endpoint is the primary finding
2. **IF** a prior code is accepted again, or after its window, because it is not normalised before the reuse check **THEN** test single-use and window invalidation separately with two submissions
3. **IF** the client receives a success field or status code it can edit before the factor is verified **THEN** switch to [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) (1 hop)
4. **IF** the second factor is reachable only through a password-reset or recovery link **THEN** switch to [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md) (1 hop)
5. **IF** a backup-code or recovery-code path has weaker checks than the primary factor **THEN** enumerate each factor path independently, because the weakest one is the finding
6. **IF** a passkey or WebAuthn flow does not distinguish discoverable from non-discoverable credentials **THEN** switch to [`saml-and-webauthn-passkey-implementation-flaws`](../saml-and-webauthn-passkey-implementation-flaws/SKILL.md) (1 hop)
7. **IF** a code issued for one account is validated against a different account **THEN** treat it as credential-flow confusion and confirm with two controlled accounts
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the factor is verified server-side, single-use, window-bound, rate-limited, and tied to the pending session with no observable gap **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Step one already returns a usable session and the factor is cosmetic | [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) | Invariant is the client-trusted success signal, not the code check |
| The passkey assertion flow conflates credential types | [`saml-and-webauthn-passkey-implementation-flaws`](../saml-and-webauthn-passkey-implementation-flaws/SKILL.md) | Invariant is assertion and credential validation, a protocol-level check |
| Many guesses pass one attempt window via concurrency | [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) | Invariant is atomic decrement of the attempt counter, not its presence |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the verification endpoint and classify the factor.** Separate the password step from the factor step and identify the factor type (TOTP, SMS or email OTP, backup code, or passkey assertion), because each has a different invalidation and binding rule.
2. **Enumerate the four properties the endpoint must hold.** Server-side verification, a per-identity attempt ceiling, single-use plus window invalidation, and binding to the pending-login session; the finding is whichever one is missing.
3. **Record a correct-code baseline.** Complete the factor once with a valid code against a controlled account and capture the exact success response, Set-Cookie, and redirect so a bypass can be measured against it.
4. **Choose the branch from the observed gap.** If no attempt counter decrements, drive a bounded guess loop; if a used code is re-accepted, test reuse and window; if the success flag is client-visible, test response manipulation; if two accounts share a flow, test credential confusion.
5. **Probe one property at a time with a differential.** For rate limiting, submit a controlled sequence of wrong codes and watch for the 429 or lockout that never comes; for reuse, resubmit the last valid code; for normalisation, submit the code with whitespace or leading zeros to see if it slips past the once-per-window check.
6. **Stop condition.** Halt when a probe either (a) completes the login without a valid current code or runs past the documented attempt budget and reverts once the missing property is enforced, (b) is blocked identically on every path, or (c) would require a real victim's live code or locking a real account. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a session granted to a controlled account without answering the current factor, or an attempt count beyond the stated ceiling, tied to one changed variable, plus the server line that skips the check or fails to decrement. A single wrong guess returning 200 is not proof.
8. **Verify impact crosses an account boundary.** Show the bypass yields access to an account the tester owns but should not reach without the factor, not merely a cosmetic UI skip in the attacker's own session.
9. **Close with the structural fix.** Enforce server-side verification, normalise the code before a single-use and window check so reuse cannot slip through, decrement a per-identity rate counter atomically, bind the code to the pending-login session, and replay the correct-code baseline plus a wrong-code loop to confirm lockout now fires.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A factor-verification POST that never returns 429 or a lockout across many wrong codes | Proves a missing attempt ceiling on the OTP or TOTP endpoint, enabling brute force on any stack |
| The same code accepted twice, or after its window, because it is not normalised before the reuse check | Proves broken single-use and window invalidation, as in codes compared before trimming or zero-padding |
| A `verified:true` or status-code field the client can edit before the factor runs | Proves client-side enforcement of the factor, a CWE-602-style trust of the response |
| A backup-code endpoint with a shorter code space or no rate limit versus the primary factor | Proves an unequal factor path where the recovery route is the weak link |
| A passkey login that accepts a non-discoverable credential where a discoverable one was required | Proves credential-flow confusion in the WebAuthn assertion check |
| A code issued for one account accepted against another account's pending session | Proves the factor is not bound to the identity, letting one flow authorise another |
| The factor step reachable directly without completing the password step | Proves the pending-login state is not enforced, so the gate is skippable |

## Worked Contrast

**Vulnerable pattern:**

```python
import hmac

def verify_otp(session, submitted):
    # No rate limit, no single-use check, compared without normalisation
    expected = current_totp(session.user_id)
    if submitted == expected:
        session.mfa_passed = True
        return issue_session(session.user_id)
    return False
```

**Hardened pattern:**

```python
import hmac

MAX_ATTEMPTS = 5

def verify_otp(session, submitted):
    if session.attempts >= MAX_ATTEMPTS:
        raise TooManyAttempts()
    session.attempts += 1  # atomic per pending-login session
    code = submitted.strip().zfill(6)  # normalise before every check
    if code in session.used_codes:
        return False  # single-use
    expected = current_totp(session.user_id)
    if hmac.compare_digest(code, expected):
        session.used_codes.add(code)
        session.mfa_passed = True
        return issue_session(session.user_id)
    return False
```

**Why this matters:** The hardened version caps attempts per pending-login session, normalises the code before the single-use and comparison checks so a reused or whitespace-padded code cannot slip past the once-per-window gate, and compares in constant time. The rate limit and single-use normalisation are the structural controls that CVE-2025-6015 and the no-rate-limit advisories were missing.

## When It Is NOT This Issue

- **Cosmetic UI skip in your own session:** editing a response so your own dashboard loads without the factor is not a finding unless it grants a session you should not have.
- **Rate limit enforced elsewhere:** if a gateway caps attempts per IP and the app also binds to the session, the absence of an app-layer 429 is not a bypass; confirm the real ceiling.
- **Expired-code rejection mistaken for reuse:** a code that fails on resubmission because the window advanced is the control working, not a single-use gap; test within one window.
- **Self-enrolment reset:** disabling your own MFA after full re-authentication is expected account management, not a bypass.
- **Test-environment seed codes:** a staging build with a fixed 000000 code is a test artefact; verify against production configuration before reporting.
- **Step-up already required:** a sensitive action that re-prompts for a fresh factor is protected even if the login factor was weak.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `mfa-and-otp-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `mfa-and-otp-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: mfa-and-otp-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287 | Mapping: A07:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `mfa-and-otp-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 9 |
| Top sources | hackerone_disclosed_reports (4), OffsecCyber (2), ctf-solver-dataset (2), CYBER_CPT/blackhills (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
