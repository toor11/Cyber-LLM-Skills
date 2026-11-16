---
name: oauth-oidc-misconfiguration-token-and-scope-abuse
description: OAuth token and scope abuse. Covers scope escalation, token substitution across clients, refresh token reuse, and audience validation gaps. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["oauth scope escalation", "token substitution", "refresh token", "audience validation"]
cwe: [CWE-601, CWE-287]
owasp: [A07:2021]
attack: [T1550]
capec: [CAPEC-657]
related: [oauth-oidc-misconfiguration, oauth-oidc-misconfiguration-redirect-uri-abuse, oauth-oidc-misconfiguration-flow-and-state-flaws, sql-injection]
parent: oauth-oidc-misconfiguration
---

# Oauth OIDC Misconfiguration Token and Scope Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Once tokens are issued, the resource server and client must validate them, and this variant targets the checks that happen after the flow: whether an access token's aud, iss, and scope are verified before it is honoured, whether a token minted for one client is accepted by another (token substitution), whether refresh tokens are single-use and rotated, and whether the authorization server grants only the scope the client is entitled to. A token accepted outside its intended audience, a refresh token that can be replayed, or a scope the consent step never bounded lets an attacker reach APIs or data beyond the granted authority. The gain is privilege or cross-client access without forging a signature. Confirmation is a protected call that succeeds with a token it should not accept, reverting when audience, scope, and rotation are enforced.

- **Precondition chain:** A resource server or client honours a bearer token without fully validating aud, iss, or scope or refresh-token single-use, an attacker can obtain a token from an adjacent client or an over-broad grant, and a protected resource acts on it.
- **Readable differential:** A protected call with a correctly scoped, correctly audienced token versus one with a token from another client or a widened scope; a finding exists when the mismatched token is honoured, and it closes once audience, issuer, scope, and rotation are enforced.
- **Empirical grounding:** CWE-287 and CWE-601; RFC 9700 (BCP 240, January 2025) is the OAuth security baseline, and token audience, issuer, and scope validation fall under CWE-287 Improper Authentication when a resource honours a token it should reject.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match the token-and-scope case **THEN** start at parent class [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) (1 hop)
2. **IF** the real problem is where the code was sent (redirect matching) **THEN** switch to [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) (1 hop)
3. **IF** the token is a JWT and the question is signature or alg **THEN** pivot to [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) (1 hop) for the integrity check
4. **IF** a token issued for client A is honoured by client B's resource server **THEN** test token substitution with two controlled clients and confirm the audience gap
5. **IF** a refresh token can be used more than once without rotation **THEN** test single-use and rotation separately with two exchanges
6. **IF** the granted scope exceeds what the client requested or is entitled to **THEN** confirm scope escalation at the authorization server, not just in the token string
7. **IF** the access token is accepted at an API that should check aud **THEN** probe audience validation by replaying the token at the wrong resource
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
9. **IF** every resource validates audience, issuer, and scope and refresh tokens are single-use and rotated **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The token's signature or alg is the weak point | [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) | Invariant is token integrity and claims signing, not audience or scope validation |
| The code reached the wrong destination first | [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | Invariant is delivery of the credential, upstream of token validation |
| A refresh token is stolen from client storage | [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md) | Invariant is token custody in the client, not server-side acceptance |
| Need parent class methodology | [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory the tokens and the resources that consume them.** Capture each access token, its aud, iss, and scope claims or introspection result, each refresh token, and the APIs that accept them.
2. **Classify what each resource validates.** Decide whether a given API checks audience, issuer, and scope, or merely that the token is signed and unexpired, because the unchecked dimension is the finding.
3. **Record a baseline call.** Make a protected request with a correctly scoped, correctly audienced token for a controlled account and capture the authoritative response.
4. **Choose the branch from the gap.** An unchecked audience routes to a token-substitution test across clients; an over-broad grant routes to a scope-escalation test; a replayable refresh token routes to a rotation test.
5. **Substitute one token property and compare.** Present a token from an adjacent controlled client, a token with a scope the consent did not grant, or a previously used refresh token, changing one property per attempt.
6. **Stop condition.** Halt when a mismatched token either (a) is honoured by a resource it should reject and the call reverts to denied when validation is enforced, (b) is refused exactly as an invalid token is, or (c) would read or mutate a real user's data. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a protected action completed with a token outside its intended audience or scope, or a refresh token accepted twice, tied to that one property, plus the missing validation. A 200 with a correctly scoped token is not proof.
8. **Separate audience, scope, and rotation failures.** Cross-client acceptance is an audience failure, excess entitlement is a scope failure, and reuse is a rotation failure; name which one broke.
9. **Close with the structural fix.** Validate aud, iss, and scope on every resource server, bind tokens to the intended audience, grant only the consented scope, and make refresh tokens single-use with rotation and reuse detection, then replay the mismatched token to confirm it is rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An access token minted for client A accepted by client B's API | Proves missing audience (aud) validation enabling token substitution across clients |
| A protected call honoured with a scope the consent step never granted | Proves scope escalation where the resource trusts the token's scope string without bounding it |
| A refresh token that mints new access tokens after prior use | Proves missing single-use and rotation, so a stolen refresh token stays valid |
| A resource server that checks signature and expiry but not aud or iss | Proves incomplete token validation, the root of substitution attacks |
| A scope widened by editing the token-exchange request and accepted | Proves the authorization server grants requested rather than entitled scope |
| An access token still accepted after the user revoked the grant | Proves missing revocation or introspection enforcement at the resource |
| The same refresh token usable from two clients | Proves the refresh token is not bound to its client, enabling reuse |

## Worked Contrast

**Vulnerable pattern:**

```python
import jwt

def require_token(authorization, jwks):
    token = authorization.split()[1]
    # Verifies signature and expiry only; audience and scope are ignored
    claims = jwt.decode(token, jwks, algorithms=["RS256"])
    return claims["sub"]
```

**Hardened pattern:**

```python
import jwt

AUDIENCE = "https://api.example"
ISSUER = "https://idp.example"
REQUIRED_SCOPE = "orders:read"

def require_token(authorization, jwks, needed=REQUIRED_SCOPE):
    token = authorization.split()[1]
    claims = jwt.decode(token, jwks, algorithms=["RS256"],
                        audience=AUDIENCE, issuer=ISSUER)
    scopes = claims.get("scope", "").split()
    if needed not in scopes:
        raise PermissionError("insufficient scope")
    return claims["sub"]
```

**Why this matters:** The defect accepts any correctly signed, unexpired token, so a token minted for a different client or with a broader scope is honoured. The fix validates aud and iss and checks the required scope before acting, which is the structural control against token substitution and scope escalation; refresh tokens additionally need single-use rotation.

## When It Is NOT This Issue

- **Correctly audienced token:** a token whose aud names this resource and whose scope covers the action is working as intended, not a substitution.
- **Scope present in token and granted:** a broad scope the user actually consented to is authorised, not an escalation.
- **Refresh rotation enforced:** a refresh token rejected on second use is the control working; test within one rotation.
- **Revocation honoured:** a token refused after the grant is revoked shows introspection is enforced.
- **Signed test token:** a self-issued token from a dev IdP accepted only in staging is an artefact unless production accepts it.
- **Bearer theft via XSS:** a token exfiltrated by script is a client-storage or XSS issue, not a server-side validation gap.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `oauth-oidc-misconfiguration-token-and-scope-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `oauth-oidc-misconfiguration-token-and-scope-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: oauth-oidc-misconfiguration-token-and-scope-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601, CWE-287 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) - Web and Application (core)
- [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) - Web and Application (leaf)
- [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `oauth-oidc-misconfiguration-token-and-scope-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601, CWE-287, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/gh_advisories (3), CYBER_CPT/hacktricks_cloud (1), CYBER_CPT/osv (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
