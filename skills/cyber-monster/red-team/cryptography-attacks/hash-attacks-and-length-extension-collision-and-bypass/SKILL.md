---
name: hash-attacks-and-length-extension-collision-and-bypass
description: Hash collision and comparison bypass. Covers practical collision use, magic hashes, type-juggled comparison and truncated digest weaknesses. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["hash collision", "magic hash", "hash comparison bypass"]
cwe: [CWE-328]
owasp: []
attack: []
capec: [CAPEC-463]
related: [hash-attacks-and-length-extension, hash-attacks-and-length-extension-length-extension, classical-and-covert-encoding, symmetric-cipher-attacks]
parent: hash-attacks-and-length-extension
---

# Hash Attacks and Length Extension Collision and Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Collision and bypass covers the family of failures where a digest does not uniquely determine the artefact. Three concrete shapes matter in review. The first is a real collision: MD5 chosen-prefix collisions are produceable in seconds and SHA-1 chosen-prefix collisions were demonstrated in SHAttered, so a digest that decides "these two files are the same" can be made to say so for two files with different content — the exploit is a substitution, where the attacker presents the benign file for approval and the colliding file for use. The second is a type-level bypass rather than a cryptographic one: PHP's `==` on two strings that both look like `0e` followed by digits compares them as floats, so `"0e123" == "0e456"` is true, which is why `md5($input) == $stored` in old PHP code is bypassable with an input whose digest starts `0e`. The third is truncation with a length mismatch: comparing `substr($hash, 0, 8)` or using `hash_equals` on values of different length short-circuits, and a magic-hash comparison that stops at a null byte (`strcmp` on `\0`) accepts anything after it. The precondition across all three is that the digest is the only thing standing between an attacker-chosen input and an accepted decision.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the comparison is `==` on a hex digest **THEN** check the language semantics first; PHP and some template engines coerce numeric-looking strings, which is a bypass with no hash weakness at all.
2. **IF** the digest is MD5 or SHA-1 and it gates an approval or a download **THEN** the substitution branch applies: two artefacts, one digest.
3. **IF** the comparison truncates the digest **THEN** compute the collision work for the truncated width before filing; 8 hex characters is 32 bits.
4. **IF** the comparison uses `strcmp`, `memcmp`, or a null-terminated string API on binary digests **THEN** the null-byte branch applies.
5. **IF** the code uses `hash_equals`, `hmac.compare_digest`, or a typed constant-time compare on full-length hex **THEN** the disposition is a control.
6. **IF** the digest protects a password **THEN** switch to [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md); the failure mode there is speed, not collision.
7. **IF** the digest is used as an identifier with no security decision attached **THEN** record it as a hardening note and say so explicitly.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the comparison, not the hash.** The primitive is rarely the problem in this skill. Write down the operator, the operand types, the truncation, and whether lengths can differ.
2. **Classify the bypass.** Numeric-string coercion, null-byte truncation, truncated comparison, or a genuine collision. Each has a different proof and a different fix.
3. **Choose the probe.** Coercion: find an input whose digest begins `0e` followed only by digits. Null byte: a digest with a `\0` early. Truncation: two inputs with the same prefix. Collision: a published collision pair, not a freshly generated one.
4. **Define the baseline-vs-probe differential.** Baseline: a wrong input is rejected. Probe: the crafted input is accepted while its digest differs from the stored one. Acceptance is the finding, and the crafted input is the artefact.
5. **Name the stop condition.** Stop at the first accepted crafted input. Do not generate collisions at scale and do not attempt to reverse a digest.
6. **State the proof.** Report the comparison expression, the operand types the language infers, the crafted input's relevant property, and the decision it flipped. If the comparison is typed and full-length, record `Verified Safe` and name the function.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `if (md5($x) == $stored)` | Loose comparison, so both sides coerce as floats when they look numeric — bypassable without any hash weakness | PHP 7 and 8 with `==`, Twig/Jinja comparisons |
| `substr(hash, 0, 8) == expected[:8]` | Truncated comparison at 32 bits, so a second preimage search is feasible offline | Legacy licence checks, short-link validation |
| `strcmp($hash, $expected) === 0` on binary digests | Null-byte truncation: the comparison stops at the first `\0` | C, older PHP, some extensions |
| `md5_file($uploaded) === $approved_md5` | A collision lets two different files share the approval digest | Upload approval, artefact mirrors |
| `hash_equals($expected, $actual)` | Correct: typed, full-length, constant-time | PHP 5.6+, Laravel, Symfony |
| `secrets.compare_digest(a, b)` on hex strings of fixed width | Correct, with the length precondition satisfied | CPython, Django |

## Worked Contrast

**Vulnerable: loose comparison on a hex digest, and a truncated check elsewhere**

```php
<?php
// "==" coerces two numeric-looking strings to floats, so an input whose md5 is
// "0e" + digits matches ANY stored digest with the same shape. The second check
// truncates to 8 hex characters, which is a 32-bit search.
$digest = md5($_POST['token']);
if ($digest == $stored_digest) {          // magic-hash bypass
    grant_access();
}
if (substr($digest, 0, 8) === substr($stored_digest, 0, 8)) {
    grant_access();                        // truncated comparison
}
```

**Hardened: strict typed comparison over the full digest**

```php
<?php
// hash_equals is length-aware and constant-time, and "===" refuses coercion, so
// neither a magic hash nor a truncated prefix can satisfy the check.
$digest = hash('sha256', $_POST['token']);
if (!is_string($stored_digest) || strlen($stored_digest) !== 64) {
    deny();
}
if (hash_equals($stored_digest, $digest)) {
    grant_access();
}
```

**Why this matters:** The left code accepts an input whose digest merely *looks* numeric because the language converts both sides to floats, and it separately accepts any input sharing eight hex characters. Neither failure requires breaking MD5. The right code compares full SHA-256 digests with a length-aware function, so both the coercion and the truncation paths are closed.

## When It Is NOT This Issue

- **`===` on full-length hex digests in PHP.** Strict comparison does not coerce, so the magic-hash bypass does not apply even with MD5. The finding would then be about MD5's collision resistance, which needs the substitution argument.
- **A digest used only for logging or cache keys.** No security decision means no bypass; say which decision, if any, consumes the value.
- **Truncation to 16 hex characters (64 bits) for an idempotency key.** The work factor is high enough that the finding is theoretical unless the attacker can choose both inputs cheaply.
- **`strcmp` on text digests.** Hex output contains no null byte, so the null-truncation argument needs a binary digest to be real.
- **A collision pair in a test fixture.** Test vectors exist to test the verifier; the finding requires the same verifier on a live path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `hash-attacks-and-length-extension-collision-and-bypass` based solely on surface keywords (`MD5 collision`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hash-attacks-and-length-extension-collision-and-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: hash-attacks-and-length-extension-collision-and-bypass
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-328`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension-length-extension`](../hash-attacks-and-length-extension-length-extension/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hash-attacks-and-length-extension-collision-and-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-328`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/ctftime (4), CYBER_CPT/gh_advisories (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
