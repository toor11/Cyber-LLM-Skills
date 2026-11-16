---
name: password-reset-and-account-recovery
description: "Exploits password reset and account recovery: host header and link poisoning, token prediction and reuse, user enumeration, response leakage, and logic flaws in security questions. Use when testing forgot-password or recovery flows."
family: web-and-application
tier: leaf
triggers: ["password reset", "account recovery", "reset token", "forgot password", "recovery flow"]
cwe: [CWE-640]
owasp: [A07:2021]
attack: []
capec: [CAPEC-50]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Password Reset and Account Recovery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The forgot-password and recovery flow issues a secret (a reset token or one-time code) and must bind it to the requesting account, deliver it only to the legitimate owner, and accept it exactly once within a short window. The weaknesses cluster around how the reset link is built and how the token is validated: an attacker-controlled Host or X-Forwarded-Host header poisons the link so the token is delivered to a collection server, tokens are predictable or not invalidated after use, the response leaks whether an account exists, or a second factor and OTP endpoint lack rate limiting. The decision point spans link construction, token lifecycle, and recovery-step authorization. The attacker gains account takeover by capturing or forging the recovery secret. Confirmation is that a poisoned link points off-domain, a token is reusable, or user existence is observably distinguishable.

- **Precondition chain:** A recovery flow mints a reset token or code, one of link construction, token binding, token lifecycle, or recovery-step rate limiting is weak, and the resulting secret is capturable, replayable, or forgeable by an attacker.
- **Readable differential:** A clean reset request versus one with a poisoned Host header or a replayed token; a finding exists when the link points off-domain or the token works twice, and it stops once links use a fixed base URL and tokens are single-use and bound.
- **Empirical grounding:** CWE-640 Weak Password Recovery Mechanism under OWASP Top 10:2025 A07 Authentication Failures; CVE-2025-27913 (Passbolt host header injection in account-recovery email links) and CVE-2025-4094 (missing OTP rate limiting) are 2025 instances of this class.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the reset link host is derived from the Host or X-Forwarded-Host header **THEN** treat link poisoning as the primary finding and test a foreign Host value
2. **IF** the token appears reusable after a successful reset **THEN** test replay by submitting the same token a second time
3. **IF** the forgot-password response differs for known versus unknown accounts **THEN** test user enumeration through status, body, or timing deltas
4. **IF** the token is short, sequential, or timestamp-derived **THEN** assess token predictability before assuming randomness
5. **IF** the reset link host comes from a trusted-proxy header **THEN** route to [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) for the header-trust invariant
6. **IF** a second factor gates the reset and lacks a rate limit **THEN** route to [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) for the OTP brute-force angle
7. **IF** the reset token is a JWT with a weak or unbound signature **THEN** route to [`jwt-attacks`](../jwt-attacks/SKILL.md) for signing and binding flaws
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** links use a fixed base URL and tokens are single-use, bound, and expiring **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The reset link host comes from the Host or X-Forwarded-Host header | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | The invariant is trusting the Host header for link construction |
| A second factor gates the reset and is brute-forceable | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | The finding is OTP rate limiting, not reset-token handling |
| The reset token is a predictable or unbound JWT | [`jwt-attacks`](../jwt-attacks/SKILL.md) | The weakness is token signing and binding, not the recovery flow shape |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the recovery flow end to end.** Identify request, token issuance, delivery channel, link construction, and the acceptance endpoint, plus any second factor. Each stage is a distinct candidate defect.
2. **Classify the dominant weakness from evidence.** Read whether the link host comes from a request header, whether the token looks random and bound, whether the response leaks account existence, and whether the OTP step is rate limited. Observed behaviour, not assumption, selects the branch.
3. **Record a clean-flow baseline.** Run a legitimate reset for a controlled account and capture the exact link host, the token shape, the acceptance response, and whether reuse is refused. This is the reference the probes perturb.
4. **Test link construction with a foreign Host.** Send the request with a modified Host or X-Forwarded-Host and observe whether the generated link host follows it, which proves delivery can be diverted.
5. **Test token lifecycle and binding separately.** Replay a used token, use a token after expiry, and try one account's token against another, so the report names the specific lifecycle failure rather than a vague token issue.
6. **Stop condition.** Halt when a probe either (a) produces a poisoned off-domain link, a reusable or cross-account token, or a clear enumeration delta, each reverting under the structural fix, (b) shows a fixed base URL and single-use bound tokens across all tests, or (c) would require taking over a real user's account to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a concrete artefact tied to one changed variable: a reset link whose host equals the injected Host, a token accepted twice, or a measurable known-versus-unknown response difference, plus the code line that trusts the header or skips invalidation. A 200 on the reset form is not proof.
8. **Close with the structural fix and verify it.** Build links from a configured base URL and validate the Host against an allowlist, mint high-entropy single-use tokens bound to the user and expiring quickly, equalise responses for known and unknown accounts, and rate-limit OTP and reset endpoints; replay each probe to confirm closure.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A reset email link whose host equals the request's Host header | Proves link construction trusts an attacker-controllable header, diverting token delivery on any framework |
| A reset token accepted a second time after a successful reset | Proves the token is not invalidated on use, a lifecycle failure on the acceptance endpoint |
| A token usable against a different account than it was issued for | Proves the token is not bound to the user, enabling cross-account takeover |
| Distinct status, body, or timing for known versus unknown emails | Proves the forgot-password endpoint leaks account existence, aiding targeted attacks |
| An OTP or reset endpoint accepting unlimited attempts | Proves a missing rate limit that makes a short code brute-forceable on the recovery step |
| A short, sequential, or timestamp-seeded token value | Proves predictable token generation that forgoes unguessable randomness |

## Worked Contrast

**Vulnerable pattern:**

```python
from flask import request

def send_reset(user):
    token = make_token(user)
    # Host header is attacker-controlled, so the link can point at a collection server
    link = "https://" + request.headers["Host"] + "/reset?token=" + token
    email(user.email, link)
```

**Hardened pattern:**

```python
import os
from flask import request

ALLOWED_HOSTS = {"app.example"}
BASE_URL = os.environ["PUBLIC_BASE_URL"]

def send_reset(user):
    if request.headers.get("Host") not in ALLOWED_HOSTS:
        raise ValueError("unexpected Host header")
    token = make_token(user)  # single-use, expiring, bound to the user id
    link = BASE_URL + "/reset?token=" + token
    email(user.email, link)
```

**Why this matters:** The vulnerable version builds the reset link from the request Host, so a poisoned header delivers the token to the attacker; the fix constructs the link from a configured base URL, validates the Host against an allowlist, and relies on a single-use bound token, so the secret can only reach the real owner.

## When It Is NOT This Issue

- **Fixed base URL already used:** links are built from server configuration, so a poisoned Host header cannot change the delivery target.
- **Token single-use and bound:** a replayed or cross-account token is refused, so a captured value is not reusable.
- **Uniform responses:** the forgot-password endpoint returns the same status, body, and timing for known and unknown accounts, closing enumeration.
- **Self-only reset:** a flow that only resets the tester's own account with no cross-user reach is expected behaviour.
- **Re-authentication required:** a sensitive change that demands the current password or a fresh factor before completing is not forgeable through the link alone.
- **Rate limit and lockout present:** an OTP endpoint that throttles and locks after a few attempts resists brute force, so a short code is not a finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `password-reset-and-account-recovery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `password-reset-and-account-recovery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: password-reset-and-account-recovery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-640 | Mapping: A07:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `password-reset-and-account-recovery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-640`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 46 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (19), hackerone_disclosed_reports (12), bugbounty-hunter-v1 (9), SecEval/owasp_wstg (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
