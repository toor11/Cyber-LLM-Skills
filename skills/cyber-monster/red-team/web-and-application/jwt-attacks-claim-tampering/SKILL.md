---
name: jwt-attacks-claim-tampering
description: JWT claim tampering and lifecycle gaps. Covers modifying claims without signature checks, missing expiry validation, audience and issuer confusion, and token replay. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["jwt claim tampering", "jwt expiry bypass", "jwt replay", "audience confusion"]
cwe: [CWE-347]
owasp: [A02:2021]
attack: [T1550]
capec: [CAPEC-121]
related: [jwt-attacks, jwt-attacks-algorithm-confusion, jwt-attacks-secret-cracking, jwt-attacks-header-injection]
parent: jwt-attacks
---

# JWT Attacks Claim Tampering - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)

## Mechanism and Preconditions

Claim tampering targets the gap after signature verification: the signature may be perfectly valid, but if the server does not enforce the registered claims, a token can be replayed past its exp, accepted for the wrong aud, trusted from an unexpected iss, or reused after logout. Here the integrity control works and the lifecycle control is missing, which is why this is a token-lifecycle invariant rather than a signature one. The attacker reuses or redirects a legitimately signed token to reach a principal, service, or time window it was never scoped for, and the gain is session extension, audience crossover, or replay. A non-destructive probe presents a validly signed token with an expired exp or a foreign aud and observes whether it is still honored.

- **Precondition chain:** The verifier validates the signature but omits one of the exp/nbf, aud, iss, or replay and revocation checks, the token can carry the stale or foreign claim under a still-valid signature, and acceptance crosses a trust boundary.
- **Readable differential:** The same signed token with exp in the future versus in the past (or with the correct aud versus a foreign one): a lifecycle-enforcing server rejects the expired or mis-audienced token, and acceptance stops once exp, aud, and iss are required.
- **Empirical grounding:** CWE-347 with token-lifecycle validation under OWASP Top 10:2025 A07 Authentication Failures. SOURCES.md has no advisory specific to exp, aud, or iss enforcement, so registered-claim validation stays at taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the claim-lifecycle profile is not yet confirmed **THEN** start at the parent class [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
2. **IF** a signed token is accepted after its exp has passed **THEN** treat missing expiry enforcement as the finding
3. **IF** a token minted for another aud is accepted by this resource server **THEN** treat audience confusion as the finding
4. **IF** the same token keeps working after logout or key rotation **THEN** treat replay and missing revocation as the finding
5. **IF** the signature itself is forgeable **THEN** switch to [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) (1 hop)
6. **IF** the token was stolen from storage rather than forged **THEN** switch to [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) (1 hop)
7. **IF** the iss claim is not pinned to a trusted issuer **THEN** treat issuer confusion across multi-tenant IdPs as the finding
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)
9. **IF** exp, aud, and iss are all verified and the signature is sound **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The signature itself is forgeable via algorithm confusion | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Invariant is signature verification, not post-verification claim checks |
| Token theft and replay is a session-lifecycle issue | [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) | Invariant is revocation and rotation, not registered-claim validation |
| Need parent class methodology | [`jwt-attacks`](../jwt-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the signature is genuinely verified.** Flip a signature byte; if it is rejected, integrity holds and the remaining question is claim enforcement. This separates lifecycle findings from signature findings.
2. **Enumerate which registered claims the verifier checks.** Read the decode call for exp/nbf verification, an audience argument, an issuer argument, and any jti or revocation lookup. Missing checks are the candidate findings.
3. **Record a valid-token baseline.** Capture acceptance of a current, correctly audienced token so each lifecycle probe has a control.
4. **Probe expiry enforcement.** Present a validly signed token whose exp is in the past; acceptance proves exp is not enforced, independent of the signature.
5. **Probe audience and issuer scoping.** Present a token whose aud names another service, then one whose iss is an unexpected issuer; acceptance isolates a missing aud or iss check.
6. **Stop condition.** Halt when a validly signed token (a) is accepted despite a stale or foreign claim and is rejected once exp, aud, and iss are required, (b) is refused for every stale or foreign claim across baselines, or (c) would require replaying another user's live token. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is server acceptance of a genuinely signed token carrying an expired, mis-audienced, or wrong-issuer claim, tied to the specific omitted check. A token that merely decodes with those claims, without being accepted on a protected route, is not proof.
8. **Close with the structural fix and verify.** Require exp and nbf, pass the expected audience and issuer to the verifier, and consult a jti or revocation store on each request, then replay the expired and foreign-aud tokens to confirm rejection.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A validly signed token accepted after its exp timestamp has passed | Proves expiry is not enforced, a token-lifecycle failure distinct from signature verification |
| A token whose aud names a different service still accepted by this resource server | Proves the audience check is missing, allowing cross-service token reuse |
| The same jti or sub honored after a logout or revocation event | Proves replay is possible because revocation state is not consulted |
| A token with an iss outside the configured trusted issuer accepted | Proves issuer pinning is absent, a risk in multi-tenant identity setups |
| Tokens missing exp, aud, or iss passing validation | Proves the verifier does not require the registered claims to be present |
| A large gap between iat and request time beyond the intended lifetime | Proves stale tokens are honored, a replay-window indicator |

## Worked Contrast

**Vulnerable pattern:**

```python
import jwt

def check(token, key):
    # Signature verified, but expiry and audience ignored: stolen or stale tokens replay
    return jwt.decode(token, key, algorithms=["RS256"],
                      options={"verify_exp": False, "verify_aud": False})
```

**Hardened pattern:**

```python
import jwt

def check(token, key):
    return jwt.decode(token, key, algorithms=["RS256"],
                      audience="api://orders", issuer="https://idp.example",
                      options={"require": ["exp", "aud", "iss"], "verify_exp": True})
```

**Why this matters:** Enforcing exp, aud, and iss ties each valid signature to a time window and a single intended service, so a token minted for another audience or already expired is refused even though its signature is genuine. The lifecycle control is restored alongside the integrity control.

## When It Is NOT This Issue

- **exp, aud, and iss all enforced:** an expired, mis-audienced, or wrong-issuer token is rejected, so there is no lifecycle gap.
- **Revocation list or jti tracking consulted:** a token reused after logout is refused, closing the replay path.
- **Claim change under an invalid signature:** altering a claim without re-signing is caught by signature verification, which is an algorithm or secret issue, not a lifecycle one.
- **Short lifetime makes replay impractical:** a token valid for seconds with strict exp leaves no meaningful replay window.
- **Audience match by design:** a token whose aud legitimately includes this service is being used as intended.
- **Clock-skew allowance within policy:** acceptance a few seconds past exp due to configured leeway is expected, not a bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jwt-attacks-claim-tampering` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jwt-attacks-claim-tampering` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jwt-attacks-claim-tampering
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`jwt-attacks`](../jwt-attacks/SKILL.md) - Web and Application (core)
- [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jwt-attacks-claim-tampering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/blackhills (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
