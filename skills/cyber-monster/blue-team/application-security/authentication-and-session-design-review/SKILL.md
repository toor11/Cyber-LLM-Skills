---
name: authentication-and-session-design-review
description: "Reviews authentication and session design: credential handling, MFA design, session lifetime and token storage decisions. Use when assessing identity architecture in an application."
family: application-security
tier: core
triggers: ["authentication design review", "session design", "mfa design review"]
cwe: [CWE-287]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Authentication and Session Design Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`csrf`](../../../red-team/web-and-application/csrf/SKILL.md)

## Mechanism and Preconditions

Authentication design is a set of state machines: credential verification, session issuance, session validation, step-up, and revocation. The review checks that each transition is enforced server-side, that the session artefact carries only an opaque identifier or a properly validated self-contained token, and that revocation actually withdraws access rather than waiting for expiry. Most real findings are gaps between the states — a password change that does not rotate the session, an MFA enrolment that does not invalidate older sessions, a logout that only clears the client.

- **CWE-287 (Improper Authentication):** the failure is a transition that any caller can trigger, or a validation step that trusts the token's claims without checking its provenance.
- ASVS 5.0.0 V6 (Authentication, 47 requirements), V7 (Session Management, 19) and V9 (Self-contained Tokens, 7) are the current clause set for this review.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** tokens are JWTs **THEN** verify algorithm allowlist, key source, `aud`, `iss`, and expiry before any claim is read; the token's own header is attacker-controlled.
2. **IF** the flow involves an external identity provider **THEN** check the OAuth/OIDC branch (state, PKCE, redirect allowlist) rather than treating it as a password login.
3. **IF** the question is where credentials are stored at rest **THEN** open `secrets-management-and-key-custody` for custody and rotation.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the states and the transitions.** Anonymous, primary-authenticated, step-up-authenticated, recovery-in-progress, and revoked. List which endpoint can move a subject between them and what evidence it requires.
2. **Check the session artefact's validation path.** For opaque sessions, confirm the lookup is server-side and the cookie is `HttpOnly`, `Secure`, `SameSite` and `__Host-` prefixed where applicable. For JWTs, confirm the verifier pins an algorithm and key set.
3. **Choose the branch by what the transition invalidates.** Credential change, MFA enrolment, role change, and logout each need a defined revocation effect; decide whether sessions are rotated, revoked, or left (and justify).
4. **Define the baseline-vs-probe differential.** Baseline: sign in on two clients. Probe: change the password on client one, then replay client two's session. A correct design rejects the second client; a design that only clears cookies on the initiating client does not.
5. **State the stop condition and the proof.** Stop when every transition has a recorded invalidation effect verified by the replay probe; proof is the second client's rejection, not the presence of a `revoke_sessions()` call.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Password change that leaves other sessions valid | Proves revocation is client-side only; the server still accepts the old session identifier on any stack. |
| JWT verifier accepting `alg: none` or the token's own key | Proves the validation step trusts attacker-controlled metadata; the standard failure on any self-contained-token implementation. |
| OTP or magic-link token with no single-use enforcement | Proves replay is possible within the validity window; the token is a bearer credential with a long life. |
| Session cookie without `__Host-` prefix or with `Domain` set | Proves cookie scope is wider than the origin, so a sibling subdomain can set or overwrite it. |

## Worked Contrast

**Vulnerable session lifecycle (password change does not revoke, token not single-use):**

```python
def change_password(user, new_password):
    user.password_hash = hash_password(new_password)
    db.commit()
    return {"ok": True}          # other sessions keep working

def consume_reset(token):
    row = db.get_reset(token)     # reusable until expires_at
    return row.user_id
```

**Hardened session lifecycle (rotation plus single-use consumption):**

```python
def change_password(user, new_password, current_session_id):
    user.password_hash = hash_password(new_password)
    user.session_epoch += 1                       # invalidates every issued session
    db.commit()
    issue_session(user, rotate_from=current_session_id)   # only this client survives
    return {"ok": True}

def consume_reset(token):
    row = db.consume_reset_atomic(token)          # UPDATE ... WHERE used_at IS NULL RETURNING
    if row is None:
        raise HTTPException(400, "invalid_or_used")
    return row.user_id
```

**Why this matters:** The first version satisfies the UX requirement and leaves every other session live, and lets a reset token be replayed until it expires. The second bumps a session epoch so all prior sessions fail validation, re-issues only the initiating client, and consumes the token atomically so two concurrent submissions cannot both succeed.

## When It Is NOT This Issue

- **Session survives because the design is stateless with short TTLs.** A five-minute access token with a revoked refresh token is acceptable if the window is documented; check the TTL before filing.
- **Single-session product.** A deliberately single-session design that logs out other clients is correct, not a gap; verify the intent before reporting missing revocation.
- **`SameSite=Lax` on a top-level navigation flow.** Lax is correct for many redirect-based flows; only `None` without `Secure` is a finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `authentication-and-session-design-review` based solely on surface keywords (`credential handling`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authentication-and-session-design-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: authentication-and-session-design-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-287`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`csrf`](../../../red-team/web-and-application/csrf/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authentication-and-session-design-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 35 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (32), CYBER_CPT/hacktricks_cloud (1), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
