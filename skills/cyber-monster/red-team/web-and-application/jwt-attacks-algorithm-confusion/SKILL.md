---
name: jwt-attacks-algorithm-confusion
description: JWT algorithm confusion and none. Covers alg none acceptance, RS256 to HS256 confusion using the public key as HMAC secret, and algorithm substitution across libraries. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["jwt alg none", "jwt algorithm confusion", "rs256 hs256", "jwt bypass"]
cwe: [CWE-347]
owasp: [A02:2021]
attack: [T1550]
capec: [CAPEC-121]
related: [jwt-attacks, jwt-attacks-secret-cracking, jwt-attacks-header-injection, jwt-attacks-claim-tampering]
parent: jwt-attacks
---

# JWT Attacks Algorithm Confusion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)

## Mechanism and Preconditions

Algorithm confusion exploits a verifier that lets the token's header alg field decide which algorithm and key type to use, so an attacker can downgrade to alg:none or re-sign an RS256 token as HS256 using the server's public key as the HMAC secret. Because the RSA public key is published in a JWKS or certificate, treating it as a symmetric secret lets the attacker produce a valid HMAC that the confused verifier checks against that same public value. The decision point is whether the verifier pins an algorithm list independent of the header; libraries that accept both families with one key material are the classic defect. The attacker forges arbitrary tokens. A non-destructive probe sends an alg:none token and a public-key-HMAC token and observes acceptance.

- **Precondition chain:** The verifier reads the algorithm from the token header, it accepts more than one algorithm family for the same key, and the key material for an asymmetric algorithm is obtainable from a published JWKS or certificate.
- **Readable differential:** A genuine RS256 token versus one re-signed as HS256 with the public key as the secret: a verifier pinned to RS256 rejects the HS256 token while a confused verifier accepts it, and acceptance disappears once the algorithm list is pinned to the single asymmetric algorithm.
- **Empirical grounding:** CWE-347. CVE-2025-68925 (header algorithm never checked), CVE-2023-48223 (fast-jwt public-key PEM matcher gap), CVE-2021-46743 (php-jwt kid-based confusion), the libjwt RSA-JWK-without-alg issue fixed in 3.3.3, and PyJWT GHSA-xgmm-8j9v-c9wx (a JWK used as an HMAC secret) all instantiate this class.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the confusion profile is not yet confirmed **THEN** start at the parent class [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
2. **IF** the verifier does not pin an algorithm list and reads alg from the header **THEN** test alg:none acceptance first as the cheapest differential
3. **IF** the service publishes an RS256 public key and the verifier also allows HS256 **THEN** test the public-key-as-HMAC-secret confusion
4. **IF** the HMAC secret is independently weak **THEN** switch to [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) (1 hop)
5. **IF** a kid or jku header selects which key verifies **THEN** switch to [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) (1 hop)
6. **IF** the library lower-cases or normalizes alg **THEN** test none, None, and nOnE casings separately
7. **IF** the stack is PyJWT, fast-jwt, php-jwt, or libjwt **THEN** check its known confusion behavior before asserting a generic result
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)
9. **IF** the verifier accepts only one asymmetric algorithm and rejects HS and none **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The HMAC secret is weak and brute-forceable rather than confused | [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) | Invariant is key entropy, not algorithm selection |
| A header field such as kid or jku steers key resolution | [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) | Invariant is key-source trust, not an alg-to-key-type mismatch |
| Need parent class methodology | [`jwt-attacks`](../jwt-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the verifier's algorithm handling.** Find the verify call and whether it passes an explicit algorithm list or infers the algorithm from the header. Inference from the header is the defect this skill targets.
2. **Establish which key material is public.** Fetch the JWKS or certificate and confirm the RSA or EC public key the server uses, since that published value becomes the candidate HMAC secret.
3. **Record a genuine-token baseline.** Capture acceptance of the unmodified RS256 token so the confusion probe has a control.
4. **Probe alg:none first.** Re-encode the token with alg none across casings (none, None, nOnE) and no signature; acceptance proves the verification branch can be disabled entirely.
5. **Probe the RS256-to-HS256 confusion.** Re-sign the claims with HMAC using the published public key bytes as the secret and header alg HS256; acceptance proves one key material is honored across two families.
6. **Stop condition.** Halt when a forged token (a) is accepted and is rejected once the algorithm list is pinned to the single asymmetric algorithm, (b) is rejected for both none and the HS confusion across baselines, or (c) would require forging another user's token for impact beyond your session. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a token the server accepts whose signature was produced with the public key as an HMAC secret (or with no signature under alg none), tied to the verifier's lack of a pinned algorithm. A decoder showing alg none is not proof without server acceptance.
8. **Close with the structural fix and verify.** Pin the verifier to a single asymmetric algorithm, use distinct key objects for distinct algorithm types, and reject none, then replay the HS256 and none tokens to confirm they are refused.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A verifier configured with algorithms accepting both an HMAC and an RSA family | Proves the confusion precondition: one key material usable across two algorithm families |
| An HS256 token accepted by a service that issues RS256 | Proves the verifier did not pin the asymmetric algorithm, the core algorithm-confusion defect |
| A token whose HMAC was computed over the published RSA public key | Proves the public-key-as-secret attack, where a known value becomes the signing key |
| alg values none, None, or nOnE accepted on any casing | Proves the none branch is reachable and case-normalization did not close it |
| A JWKS fetch followed by authenticated requests using HS256 from the same client | Proves the public key was retrieved and repurposed as an HMAC secret |
| The verifier rejects HS256 and none and accepts only one asymmetric algorithm | Proves the algorithm list is pinned, a working control rather than a finding |

## Worked Contrast

**Vulnerable pattern:**

```python
import jwt

# Both families accepted with the SAME key material: an RS256 public key works as an HS256 secret
def verify(token, rsa_public_pem):
    return jwt.decode(token, rsa_public_pem, algorithms=["RS256", "HS256"])
```

**Hardened pattern:**

```python
import jwt

def verify(token, rsa_public_pem):
    # Asymmetric only: an HS256 token is rejected before the public key is ever used as a secret
    return jwt.decode(token, rsa_public_pem, algorithms=["RS256"])
```

**Why this matters:** Restricting the algorithm list to RS256 breaks the confusion because an HMAC-signed token can no longer be validated with the RSA public key, matching the fast-jwt and Jervis fixes. The key type and algorithm are decided by the server, not the header.

## When It Is NOT This Issue

- **Single asymmetric algorithm pinned:** the verifier accepts only RS256 or only ES256, so an HS256 or none token is rejected before any key is used.
- **Separate keys for separate algorithms:** HMAC and RSA use distinct, non-overlapping key material, so the public key cannot double as a secret.
- **alg:none rejected on all casings:** none, None, and nOnE all fail, so the none branch is closed.
- **Public key not obtainable:** without a published JWKS or certificate, the confusion attack has no key material to repurpose.
- **HS probe fails because HMAC is keyed off the right secret:** an HS256 token rejected because the server never keys HMAC off the public value is not confused.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jwt-attacks-algorithm-confusion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jwt-attacks-algorithm-confusion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jwt-attacks-algorithm-confusion
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`jwt-attacks`](../jwt-attacks/SKILL.md) - Web and Application (core)
- [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jwt-attacks-algorithm-confusion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/osv (3), CYBER_CPT/gh_advisories (2), CYBER_CPT/pentesterlab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
