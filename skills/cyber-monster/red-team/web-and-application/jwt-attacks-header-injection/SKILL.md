---
name: jwt-attacks-header-injection
description: JWT header injection abuse. Covers kid path traversal and SQL injection, jku and x5u URL injection pointing at attacker keys, and embedded jwk trust. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["jwt kid injection", "jku injection", "x5u", "jwt header injection"]
cwe: [CWE-347]
owasp: [A02:2021]
attack: [T1550]
capec: [CAPEC-121]
related: [jwt-attacks, jwt-attacks-algorithm-confusion, jwt-attacks-secret-cracking, jwt-attacks-claim-tampering]
parent: jwt-attacks
---

# JWT Attacks Header Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)

## Mechanism and Preconditions

JWT header injection abuses the key-resolution fields the verifier reads from the token itself: kid names which key to load, jku and x5u are URLs the verifier fetches keys from, and jwk embeds a key inline. If any of these is trusted without constraint, the attacker steers verification to a key they control (a traversed file, a JWKS on their host, or an inline public key), so a token they signed validates. The decision point is where the verification key comes from; a secure verifier resolves keys through a closed server-side map and ignores token-supplied key sources. The attacker forges tokens by supplying both the token and the key that checks it. A non-destructive probe sets jku or x5u to an assessor host or embeds a jwk and observes acceptance or an outbound fetch.

- **Precondition chain:** The verifier derives the verification key from a token header field (kid, jku, x5u, or jwk), that field is not constrained to a trusted set, and the attacker can host or embed the matching key.
- **Readable differential:** A token with a normal kid versus one whose jku or x5u points at an assessor-hosted JWKS or carries an inline jwk: only the manipulated token causes the server to fetch or trust the attacker key, and that behavior stops once kid resolves through a closed map and jku, x5u, and jwk are ignored.
- **Empirical grounding:** CWE-347. CVE-2021-46743 (php-jwt kid-based key selection), PyJWT GHSA-993g-76c3-p5m4 (PyJWKClient accepting non-HTTP(S) URIs) and GHSA-jq35-7prp-9v3f (PyJWK allow-list bypass), plus the libjwt RSA-JWK-without-alg case fixed in 3.3.3, anchor the kid, jku, and embedded-jwk paths.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the header-field key-selection profile is not yet confirmed **THEN** start at the parent class [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
2. **IF** a kid value is used to read a key from a file path or a SQL lookup **THEN** test path traversal and injection in kid
3. **IF** a jku or x5u URL is fetched to obtain the verification key **THEN** test redirection to an assessor-hosted JWKS
4. **IF** a self-contained jwk header is honored **THEN** test an embedded attacker public key
5. **IF** the kid lands in a SQL query **THEN** switch to [`sql-injection`](../sql-injection/SKILL.md) (1 hop)
6. **IF** the public key is reused as an HMAC secret through an alg swap **THEN** switch to [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) (1 hop)
7. **IF** the stack is PyJWT with PyJWKClient fetching keys **THEN** check whether non-HTTPS or non-allowlisted jku URIs are accepted
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md)
9. **IF** kid resolves through a closed server-side map and jku, x5u, and jwk are ignored **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The kid value is concatenated into a SQL lookup | [`sql-injection`](../sql-injection/SKILL.md) | Invariant is SQL parsing of the kid, a nested injection sink |
| The public key is reused as an HMAC secret via an alg swap | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Invariant is algorithm selection, not key-URL or jwk trust |
| Need parent class methodology | [`jwt-attacks`](../jwt-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate how the verifier obtains its key.** Read whether the key comes from a kid lookup, a jku or x5u fetch, an inline jwk, or a fixed server-side key. Any token-derived key source is the decision point.
2. **Classify the key-source trust.** Determine whether kid is mapped through a closed dictionary or used as a path or query, and whether jku, x5u, and jwk are honored at all. This routes to traversal, redirection, or embedded-key testing.
3. **Record a normal-key baseline.** Send a token with a legitimate kid and capture acceptance so each manipulation has a control.
4. **Probe kid resolution.** Point kid at a predictable or empty key source (a traversal path, or a value a SQL lookup returns empty); a token signed with the resulting key that is accepted proves kid steers key selection.
5. **Probe jku, x5u, and jwk.** Set jku or x5u to an assessor-hosted JWKS and embed a jwk with an attacker key; an outbound fetch to the host or acceptance of the inline key proves the key source is attacker-controllable.
6. **Stop condition.** Halt when a token signed with an attacker key (a) is accepted and is rejected once kid uses a closed map and jku/x5u/jwk are ignored, (b) is refused for every key-source manipulation across baselines, or (c) would require forging another principal's token for impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is acceptance of a token verified with a key the attacker supplied or hosted, tied to the specific header field (kid, jku, x5u, or jwk), or an outbound key fetch to the assessor host. A kid containing traversal characters that resolves to a trusted key is not proof.
8. **Close with the structural fix and verify.** Resolve kid through a closed server-side map, ignore jku, x5u, and jwk headers entirely, and pin the JWKS host, then replay the manipulated-header tokens to confirm they are rejected and no outbound fetch occurs.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A kid value containing ../ or a NUL used to load a verification key | Proves kid is treated as a file path, letting an attacker point verification at a predictable key |
| A jku or x5u URL whose host is not the trusted issuer being fetched | Proves the verifier retrieves keys from an attacker-controllable location |
| A token carrying an inline jwk header that the verifier honors | Proves embedded-key trust, so the attacker supplies both the token and its key |
| A kid value flowing into a SQL or filesystem lookup | Proves a nested injection sink reachable through the header key id |
| PyJWKClient accepting a non-HTTPS or non-allowlisted jku URI | Proves the key-source restriction is missing on the PyJWT stack |
| kid resolved through a closed server-side map with jku, x5u, and jwk ignored | Proves the structural control holds, a working key-resolution design |

## Worked Contrast

**Vulnerable pattern:**

```python
import jwt, requests

def verify(token):
    header = jwt.get_unverified_header(token)
    # kid and jku from the attacker decide which key verifies the token
    key = requests.get(header["jku"]).json()["keys"][0]
    return jwt.decode(token, key, algorithms=["RS256"])
```

**Hardened pattern:**

```python
import jwt

TRUSTED_KEYS = {"2024-rot": open("/etc/keys/2024-rot.pub").read()}

def verify(token):
    header = jwt.get_unverified_header(token)
    key = TRUSTED_KEYS.get(header.get("kid"))  # closed map; jku/x5u/jwk ignored
    if key is None:
        raise ValueError("unknown key id")
    return jwt.decode(token, key, algorithms=["RS256"])
```

**Why this matters:** Resolving kid through a closed server-side map and ignoring jku, x5u, and jwk means the token can only be verified with a key the server already trusts, never one the attacker hosts or embeds. The key source is server-controlled.

## When It Is NOT This Issue

- **kid resolved through a closed map:** the key id only selects from a server-side dictionary and unknown ids are rejected, so traversal has no effect.
- **jku, x5u, and jwk ignored:** the verifier never fetches or trusts token-supplied key sources, so redirection and inline keys fail.
- **jku host allowlisted to the issuer:** a URL outside the trusted host is refused, closing the redirection path.
- **Embedded jwk cross-checked against a trusted thumbprint:** an inline key accepted only when it matches a pinned key is not attacker-controllable.
- **kid value not used as a path or query:** a kid treated purely as an opaque lookup token has no traversal or injection surface.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `jwt-attacks-header-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jwt-attacks-header-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: jwt-attacks-header-injection
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
- [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jwt-attacks-header-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/gh_advisories (2), CYBER_CPT/osv (2), CYBER_CPT/pentesterlab (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
