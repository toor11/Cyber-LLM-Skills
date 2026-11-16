---
name: authentication-bypass-default-and-weak-credentials
description: Default and weak credential exploitation. Covers vendor default credentials, predictable first-run passwords, credential reuse across services, and spraying under lockout thresholds. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["default credentials", "weak password", "credential spraying", "first run password"]
cwe: [CWE-287]
owasp: [A07:2021]
attack: [T1078]
capec: [CAPEC-115]
related: [authentication-bypass, authentication-bypass-forced-browsing, authentication-bypass-response-manipulation, authentication-bypass-header-and-proxy-trust]
parent: authentication-bypass
---

# Authentication Bypass Default and Weak Credentials - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant exploits credentials that were never a secret: a vendor factory pair shipped in the manual, a first-run setup that seeds a predictable admin account, a password derived from a serial number or MAC, or a human-chosen password weak enough to guess. The gate itself performs a correct comparison, but the secret side of that comparison is public or low-entropy, so the attacker supplies the known value and authenticates in a single request. Where a direct default does not exist, the same weakness appears as spraying a common password across many accounts under a login that never enforces a lockout or rate limit. The attacker lands as whatever identity the default or guessed credential owns, often administrator, and confirmation is simply that the known pair is accepted while a random control pair is not.

- **Precondition chain:** the credential store contains a public, predictable, or low-entropy secret for a reachable account, the login gate accepts that value without additional proof, and no lockout or rate limit prevents the single confirming attempt.
- **Readable differential:** a login with the documented default or a common password versus the same request with a random control value; a finding exists when only the known value is accepted and issues a session, and it closes once the default is removed or rotation is forced.
- **Empirical grounding:** CWE-287 Improper Authentication with CWE-1392 Use of Default Credentials and CWE-521 Weak Password Requirements under OWASP Top 10:2025 A07 Authentication Failures; the missing-rate-limit aspect that enables spraying is shown in 2025 by CVE-2025-6015 (HashiCorp Vault MFA rate-limit bypass with TOTP reuse) and CVE-2025-4094 (DIGITS plugin OTP validation without rate limiting).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match default and weak credentials **THEN** start at parent class [`authentication-bypass`](../authentication-bypass/SKILL.md) (1 hop) for general triage
2. **IF** a documented vendor pair such as admin:admin may still be active on the panel **THEN** attempt the single documented pair against a random control pair before anything else
3. **IF** the device exposes a first-run or setup wizard **THEN** check whether the install path is still reachable after provisioning and can seed an admin
4. **IF** the login has no lockout or rate limit and spraying is possible **THEN** observe the threshold behaviour read-only; cite the missing control rather than running a wide spray
5. **IF** the first-run password is derived from a serial number, MAC, or timestamp **THEN** model it as a predictable seed credential rather than a guess
6. **IF** the credential also unlocks a second service through reuse **THEN** record credential reuse as a separate impact path across services
7. **IF** a second factor is enforced after the password stage **THEN** a valid default alone no longer authenticates; route to [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the documented pair is rejected and no weak or predictable credential is accepted **THEN** STOP and record a verified non-finding rather than escalating into a brute-force run

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Login succeeds but the issued session or token is then forgeable | [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) | Invariant moves to signing-key strength once the credential is valid |
| The weak secret is a reset or recovery token, not a login password | [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md) | Invariant is recovery-token entropy and binding, a different gate |
| A second factor is enforced after the password step | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | A valid default password no longer authenticates; the step-up gate governs |
| Need parent class methodology | [`authentication-bypass`](../authentication-bypass/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fingerprint the product and its documented credentials.** Identify the vendor, model, and firmware from banners, favicons, and panel markup, then look up the factory pair and any first-run behaviour. The secret you are testing is public, so the work is matching the target to its known defaults.
2. **Locate the login gate and the setup path separately.** A product can be safe on login yet expose an open install wizard that seeds a fresh admin. Record both the authentication endpoint and any `/setup` or `/install` route.
3. **Record a control baseline.** Submit one random username and password pair and capture status, any `Set-Cookie`, and body shape. This is the rejected-credential reference the known pair is compared against.
4. **Attempt the known value once.** Submit the documented default or the single most likely weak password exactly once, respecting any lockout, and compare the response to the control. A session or a differing status is candidate confirmation.
5. **Observe the threshold rather than exhaust it.** If no direct default exists, confirm whether a lockout or 429 ever appears across a few failed attempts on one account; the absence of that control is the spraying finding, which you report without running a wide campaign.
6. **Stop condition.** Halt when either (a) the known or weak credential is accepted and issues a session while the control is rejected, (b) the known pair is refused and no predictable or low-entropy credential works, or (c) proceeding would require a broad guessing run against real accounts. Case (a) confirms, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is a session issued to a public or predictable credential, shown by a differential against a random control pair, plus the source of that credential such as the vendor manual or an unchanged first-run seed. A login form that merely accepts input, or a single lucky guess without a control, is not proof.
8. **Close with the structural fix.** Remove the default account or force a unique random secret with mandatory rotation at first use, enforce a password policy that rejects common values, and add a lockout or rate limit on the login and setup paths. Verify by replaying the known pair against the hardened build and confirming it is now rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A documented vendor pair such as `admin:admin` authenticating on the running panel | Proves an unchanged factory credential on the appliance or app, a single-request takeover |
| A first-run setup wizard reachable after the product is provisioned | Proves an open installation path that can seed a new administrator on self-hosted stacks |
| No lockout or 429 after repeated failures for one account | Proves the gate permits unbounded guessing, enabling low-and-slow spraying; CVE-2025-4094 and CVE-2025-6015 are 2025 instances |
| A password equal to the username or a top-common value accepted at signup | Proves a weak-credential policy gap on the registration path (CWE-521) |
| The same credential unlocking both an admin panel and a public service | Proves credential reuse that turns one leak into multi-service access |
| A first-run password derived from a serial number or MAC address | Proves a deterministic seed credential on vendor devices |
| A TOTP code accepted a second time within the same validation window | Proves second-factor reuse, as in the Vault TOTP normalisation flaw CVE-2025-6015 |

## Worked Contrast

**Vulnerable pattern:**

```python
DEFAULT_USER = "admin"
DEFAULT_PASS = "admin"


def login(username, password):
    # A seeded factory account that is never forced to change
    if username == DEFAULT_USER and password == DEFAULT_PASS:
        return issue_session(username)
    return authenticate_against_store(username, password)
```

**Hardened pattern:**

```python
import secrets


def provision_first_run():
    # A unique one-time secret per install, rotation required before use
    temp = secrets.token_urlsafe(18)
    store.create_admin(password_hash=hash_password(temp), must_rotate=True)
    write_install_log(temp)


def login(username, password):
    user = store.get(username)
    if user is None or not verify_password(password, user.password_hash):
        return None
    if user.must_rotate:
        return require_password_change(user)
    return issue_session(username)
```

**Why this matters:** A shared, guessable default pair grants access on every deployment that skipped the manual change. The control seeds a per-install random secret, forces rotation before the account is usable, and removes the hardcoded branch entirely, so no publicly known value authenticates.

## When It Is NOT This Issue

- **Default already changed:** a panel that ships with a factory pair but rejects it because the operator rotated it is hardened; the manual-documented value is not a finding once replaced.
- **Lab or honeypot account:** a credential that only works against a seeded test tenant or an intentional honeypot is a test-environment artefact, not production access.
- **Lockout fires on the first attempts:** a login that locks or throttles after a few failures already carries the compensating control that neutralises spraying.
- **Strong unique first-run secret:** a setup that generates a random per-install password and forces rotation is behaving correctly even though a setup path exists.
- **Guess with no control comparison:** a single successful login without a rejected random control does not establish that the credential was weak rather than legitimately owned.
- **Credential valid only for the researcher's own account:** reusing your own known password is in-scope for that account and proves nothing about others.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authentication-bypass-default-and-weak-credentials` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authentication-bypass-default-and-weak-credentials` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authentication-bypass-default-and-weak-credentials
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
- [`authentication-bypass-header-and-proxy-trust`](../authentication-bypass-header-and-proxy-trust/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authentication-bypass-default-and-weak-credentials` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 32 |
| Distinct dataset sources | 13 |
| Top sources | CYBER_CPT/L5/ctf_search (7), bugbounty-hunter-v1 (5), OffsecCyber (4), hackerone_disclosed_reports (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
