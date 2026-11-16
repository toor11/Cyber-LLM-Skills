---
name: jwt-attacks
description: "Exploits JSON Web Tokens: algorithm confusion and none, weak HMAC secret cracking, key confusion and injection, claim tampering, kid and jku abuse, and signature-stripping paths. Use when an application issues or validates JWTs."
family: web-and-application
tier: core
triggers: ["jwt", "json web token", "jwt none", "alg confusion", "kid injection", "jwt cracking", "bearer token"]
cwe: [CWE-347]
owasp: [A02:2021]
attack: [T1550]
capec: [CAPEC-121]
related: [jwt-attacks-algorithm-confusion, jwt-attacks-secret-cracking, jwt-attacks-header-injection, sql-injection]
---

# JWT Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)

## Mechanism and Preconditions

A JSON Web Token is a header.payload.signature triple where only the signature protects integrity, so every security property depends on the verifier recomputing and checking that signature with a key and algorithm the server, not the token, chooses. Attacks target the verifier's decisions: whether it honors an alg:none or a swapped algorithm, whether the HMAC secret is guessable, whether a kid, jku, or jwk header can point verification at an attacker key, and whether registered claims such as exp, aud, and iss are enforced after the signature passes. The break is always a verification step the server skipped or delegated to attacker-controlled input. The attacker gains forged identity or elevated claims. Non-destructive confirmation re-signs or re-encodes a token and observes whether the server accepts it.

- **Precondition chain:** The application authorizes requests from a JWT, the verifier makes at least one trust decision from token-supplied data (algorithm, key id, or key URL) or omits a claim check, and a forged or tampered token changes the authenticated principal or scope.
- **Readable differential:** An unmodified token versus a minimally altered one (alg set to none, a flipped signature byte, or a changed claim): a correct verifier rejects every alteration, and acceptance of any of them localizes the missing check.
- **Empirical grounding:** CWE-347 Improper Verification of Cryptographic Signature. CVE-2025-68925 (a build tool whose JWT verifier never checked the header algorithm, fixed 2.2) and the PyJWT 2.13.0 security release (five advisories including GHSA-xgmm-8j9v-c9wx) anchor the family.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the header alg can be set to none or swapped between the HS and RS families **THEN** switch to [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) (1 hop)
2. **IF** the token is HS256 with a possibly weak or guessable secret **THEN** switch to [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) (1 hop)
3. **IF** a kid, jku, x5u, or embedded jwk header steers key selection **THEN** switch to [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) (1 hop)
4. **IF** the signature verifies but exp, aud, or iss are not enforced **THEN** switch to [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) (1 hop)
5. **IF** the credential is a SAML assertion rather than a JWT **THEN** switch to [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) (1 hop)
6. **IF** the weakness is in the OAuth redirect or code flow, not the token signature **THEN** switch to [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) (1 hop)
7. **IF** the token is an opaque reference validated by introspection, not a JWS **THEN** treat it as a session reference and assess the introspection endpoint instead
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)
9. **IF** the verifier pins algorithms server-side, binds the key, and enforces registered claims **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The credential is a SAML assertion, not a JWS token | [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) | Invariant is XML signature wrapping, not JWS verification |
| The flaw is in the authorization-code or redirect flow | [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) | Invariant is redirect and code handling, not token integrity |
| Target matches `jwt-attacks-algorithm-confusion` | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `jwt-attacks-secret-cracking` | [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `jwt-attacks-header-injection` | [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `jwt-attacks-claim-tampering` | [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Decode the token and locate the verifier.** Split the header, payload, and signature, and find the server call that verifies it. Record the issuer, the algorithm in the header, and which library performs verification. The verify call is the decision point.
2. **Classify which trust decision the verifier delegates.** Determine whether it reads alg from the header, resolves a key from kid/jku/jwk, relies on a shared HMAC secret, or skips claim checks. Each choice routes to a specific child invariant.
3. **Record an unmodified baseline.** Send the genuine token and capture the authenticated response. This control is the shape every altered token is compared against.
4. **Apply the cheapest integrity differential first.** Flip one signature byte and resend; rejection confirms the signature is actually checked, acceptance localizes a complete verification bypass before any key work.
5. **Escalate one verification property at a time.** Test alg:none, then a claim change without re-signing, then a key-source manipulation, stopping at the first that is accepted. The deeper tests only change the specific broken control, not the fact of a finding.
6. **Stop condition.** Halt when an altered token (a) is accepted and the change reverts once the verifier pins algorithm, key, and claims, (b) is rejected for every alteration across two baselines, or (c) would require forging a real user's token to cause harm beyond your own session. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a server-accepted token that differs from the genuine one by a single controlled change (alg, signature byte, or claim), tied to the exact missing verification step. Editability in a JWT decoder is not proof; the server must accept the altered token.
8. **Close with the structural fix and verify.** Pin the algorithm list server-side, bind the verification key to the issuer, enforce exp/aud/iss, and ignore token-supplied key sources, then replay the accepted alteration to confirm it is now rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A JWT presented with header alg equal to none on a protected route | Proves the none branch was attempted; acceptance means the verifier trusts the header over a pinned algorithm |
| The same request accepted after a single signature byte is flipped | Proves the signature is not actually verified, the root failure for any JWS consumer |
| A changed sub or role claim accepted without re-signing | Proves the payload is trusted beyond what the signature covers on this verifier |
| A verifier call that passes the token-supplied alg into the verify routine | Proves the algorithm decision is delegated to attacker input rather than fixed server-side |
| One sub claim arriving from many source IPs in a short window | Proves a shared forged token is circulating, a hunt signal on the auth gateway |
| No issuance record at the IdP for a jti the resource server accepted | Proves the token was minted outside the issuer, consistent with forgery |

## Worked Contrast

**Vulnerable pattern:**

```python
import jwt

def whoami(token, public_key):
    # No algorithms pinned: alg:none and HS/RS confusion both slip through
    claims = jwt.decode(token, public_key, options={"verify_signature": True})
    return claims["sub"]
```

**Hardened pattern:**

```python
import jwt

def whoami(token, public_key):
    # The verifier, not the token header, decides the algorithm and enforces claims
    claims = jwt.decode(token, public_key, algorithms=["RS256"],
                        audience="api://orders", issuer="https://idp.example",
                        options={"require": ["exp", "iss", "aud"]})
    return claims["sub"]
```

**Why this matters:** Pinning algorithms to RS256 means the header alg field can no longer select none or HS256, and the require option forces the registered claims to be present and checked. Verification decisions move from the token to the server.

## When It Is NOT This Issue

- **Algorithm pinned server-side:** the verifier fixes the algorithm and key, so a header alg change is ignored and not a finding.
- **Signature actually verified:** a flipped signature byte is rejected, confirming integrity is enforced even if claims look editable in a decoder.
- **Opaque token, not a JWS:** a reference token validated by introspection has no client-verifiable signature, so JWT signature attacks do not apply.
- **Self-scoped claim change only:** a tampered token that alters nothing beyond the attacker's own session crosses no trust boundary.
- **Decoder shows editable payload:** seeing claims in a JWT debugger is not proof; the server must accept the altered token.
- **Short-lived token with enforced exp and aud:** a token rejected once stale or mis-audienced is operating as designed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jwt-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jwt-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jwt-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jwt-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 37 |
| Distinct dataset sources | 11 |
| Top sources | bugbounty-hunter-v1 (15), OffsecCyber (9), CYBER_CPT/ctf_search (3), hackerone_disclosed_reports (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 1 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
