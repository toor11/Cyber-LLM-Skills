---
name: jwt-attacks-secret-cracking
description: JWT secret cracking and weak key exploitation. Covers offline HMAC secret recovery with hashcat and john, weak key patterns, and re-signing forged claims after recovery. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["jwt cracking", "jwt secret", "hashcat jwt", "weak jwt key"]
cwe: [CWE-347]
owasp: [A02:2021]
attack: [T1550]
capec: [CAPEC-121]
related: [jwt-attacks, jwt-attacks-algorithm-confusion, jwt-attacks-header-injection, jwt-attacks-claim-tampering]
parent: jwt-attacks
---

# JWT Attacks Secret Cracking - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)

## Mechanism and Preconditions

When a JWT is signed with an HMAC algorithm (HS256, HS384, or HS512), the entire integrity of the token rests on a single shared secret, and if that secret has low entropy (a dictionary word, a framework default, a hardcoded string) it can be recovered offline from one captured token by recomputing HMAC over the known header and payload for each candidate until the signatures match. No request to the target is needed during the crack; the oracle is the captured signature itself. The decision point is key strength and provenance, not the verification logic. Once the secret is recovered the attacker signs arbitrary claims. A non-destructive check tests candidate secrets offline and confirms a match by signature equality, never by probing the live service.

- **Precondition chain:** The token uses an HMAC algorithm, the signing secret has insufficient entropy or is a known or default value, and the assessor holds at least one genuine token to crack against.
- **Readable differential:** A captured token tested against a wordlist versus against a high-entropy random key: only a weak secret yields a candidate whose recomputed signature equals the captured one, and that match becomes impossible once the key is a 256-bit manager-sourced value.
- **Empirical grounding:** CWE-347 combined with weak-key entropy. SOURCES.md has no dedicated HMAC-cracking CVE; the closest anchor is PyJWT GHSA-xgmm-8j9v-c9wx, where a public RSA key is accepted as the HMAC secret, making the key a known value. Otherwise this stays at taxonomy level for weak and default secrets.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the weak-key profile is not yet confirmed **THEN** start at the parent class [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
2. **IF** the header alg is HS256, HS384, or HS512 (a shared secret signs the token) **THEN** capture one token and attempt offline dictionary recovery
3. **IF** the alg is asymmetric such as RS, ES, or PS **THEN** offline secret cracking does not apply; reconsider confusion or header injection
4. **IF** no verification happens at all (alg none or confusion) **THEN** switch to [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) (1 hop)
5. **IF** the token was obtained from client storage, not cracked **THEN** switch to [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md) (1 hop)
6. **IF** the secret appears to be a framework default or a hardcoded string **THEN** check source and config inventories for the literal value
7. **IF** a candidate secret recomputes the captured signature exactly **THEN** that match is the confirmation and no live requests are required
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)
9. **IF** the HMAC key is high-entropy, manager-sourced, and rotated **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No signature is actually verified via alg none or confusion | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Invariant is whether verification runs, not whether the key is weak |
| The token is stolen rather than forged | [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md) | Invariant is token confidentiality at rest, not key strength |
| Need parent class methodology | [`jwt-attacks`](../jwt-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the algorithm is HMAC.** Read the header alg; only HS256/384/512 rest on a crackable shared secret. An asymmetric alg routes away from this skill.
2. **Capture one genuine token.** Obtain a single valid token over the authorized engagement; this is the offline oracle and no further live interaction is needed to crack.
3. **Establish the crack baseline.** Note the header and payload bytes and the captured signature, since recovery is recomputing HMAC over those exact bytes for each candidate.
4. **Run a bounded dictionary pass offline.** Test a wordlist and common framework defaults; a candidate whose recomputed signature equals the captured one is the secret. Keep the work offline to avoid touching the service.
5. **Compare against a strong-key control.** Confirm that a high-entropy random key produces no match, so a hit genuinely reflects weak entropy rather than a procedural error.
6. **Stop condition.** Halt when the crack (a) yields a secret that recomputes the captured signature and would let forged claims be accepted, (b) exhausts the wordlist with no match, or (c) would require online brute force against the live verifier. Case (a) confirms, (b) is a non-finding for weak-secret scope, (c) is out of scope.
7. **State what counts as proof.** Proof is a recovered secret demonstrated by signature equality on the captured token (and ideally re-verified against a second captured token), plus the HMAC algorithm in use. A single coincidental match that does not re-verify is not proof.
8. **Close with the structural fix and verify.** Replace the secret with at least 256 bits of CSPRNG entropy sourced from a secret manager, rotate it, and prefer asymmetric signing for externally verified tokens, then re-run the wordlist to confirm no candidate matches.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A header alg of HS256, HS384, or HS512 on externally reachable tokens | Proves a shared secret guards integrity, the precondition for offline cracking |
| A captured token whose signature a wordlist candidate reproduces exactly | Proves the secret is recoverable offline; signature equality is the confirmation oracle |
| A hardcoded or default HMAC secret found in source or container images | Proves a known-value key that forges tokens without any cracking effort |
| An HMAC secret shorter than 32 bytes or equal to a dictionary word | Proves insufficient key entropy on the signing configuration |
| No key-rotation events in the secret-manager audit log over long periods | Proves a static secret whose compromise has an unbounded lifetime |
| A 256-bit CSPRNG secret injected from a secret manager and rotated | Proves adequate key strength, a working control rather than a finding |

## Worked Contrast

**Vulnerable pattern:**

```python
import jwt

SECRET = "secret"  # short, guessable: offline hashcat recovers it in seconds

def issue(claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")
```

**Hardened pattern:**

```python
import jwt, os

# At least 256 bits of CSPRNG entropy, injected from a secret manager, rotated on a schedule
SECRET = os.environ["JWT_HS256_KEY"]
assert len(SECRET.encode()) >= 32

def issue(claims):
    return jwt.encode(claims, SECRET, algorithm="HS256")
```

**Why this matters:** A 256-bit random key sourced from a secret manager has no entry in any wordlist, so offline hashcat or john recovery is infeasible, unlike a dictionary word baked into source. Key provenance and entropy, not the verify call, are what change.

## When It Is NOT This Issue

- **High-entropy manager-sourced secret:** a 256-bit random key has no wordlist entry, so offline cracking is infeasible.
- **Asymmetric signing:** an RS256 or ES256 token has no shared secret to crack; this is a confusion or header question instead.
- **No token available to crack against:** without a captured genuine token, there is no offline oracle and no finding to assert.
- **Secret rotated faster than a crack completes:** a key that changes before recovery is practical limits the exposure window.
- **Candidate match not reproducible:** a one-off signature coincidence that does not re-verify against a second token is not a recovered secret.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jwt-attacks-secret-cracking` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jwt-attacks-secret-cracking` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jwt-attacks-secret-cracking
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
- [`jwt-attacks-header-injection`](../jwt-attacks-header-injection/SKILL.md) - Web and Application (leaf)
- [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jwt-attacks-secret-cracking` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/vulhub (2), cyber-security/security-code (1), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
