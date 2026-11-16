---
name: type-juggling-and-loose-comparison
description: Exploits loose type comparison and coercion across PHP, JavaScript and other dynamic languages, including magic hashes, array and string confusion, and numeric string tricks. Use when authentication, token or hash comparison uses non-strict equality.
family: web-and-application
tier: leaf
triggers: ["type juggling", "loose comparison", "magic hash", "php juggling", "weak comparison", "0e hash"]
cwe: [CWE-843]
owasp: [A04:2021]
attack: []
capec: [CAPEC-463]
related: [type-juggling-and-loose-comparison-php-juggling, type-juggling-javascript-other-languages, sql-injection, cross-site-scripting]
---

# Type Juggling and Loose Comparison - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Loose, non-strict comparison operators coerce their operands to a common type before comparing, so two values that are unequal as strings can compare equal after coercion. The decision point is the comparison operator and the types reaching it in a security check such as a password or token comparison or an access flag. Classic cases are magic hashes, where a digest like `0e` followed by digits coerces to the float zero so two different hashes compare equal, and array-versus-string confusion, where a helper returns null or false and loose comparison treats it as a match. The attacker supplies a value whose coerced form equals the expected secret without knowing it. Confirmation is a value that is unequal under strict comparison yet equal under the loose operator at the exact security check.

- **Precondition chain:** A security check uses a loose comparison or implicit coercion, the attacker controls one operand value and its type, and the coerced forms of the two operands can be made to match.
- **Readable differential:** Submit a value that fails strict equality but passes loose equality at the check; a finding exists when the loose operator admits the attacker while strict comparison rejects, and it closes when the check is switched to a type-safe comparison.
- **Empirical grounding:** CWE-843 Access of Resource Using Incompatible Type anchors this class; the skill maps it to OWASP A04:2021, and in OWASP Top 10:2025 a coerced authentication check surfaces under A07:2025 Authentication Failures. SOURCES.md lists no advisory specific to loose comparison, so this entry stays at the taxonomy level rather than citing a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the comparison is in PHP code **THEN** switch to [`type-juggling-and-loose-comparison-php-juggling`](../type-juggling-and-loose-comparison-php-juggling/SKILL.md) (1 hop)
2. **IF** the comparison is in JavaScript, Python, Ruby, or another dynamic language **THEN** switch to [`type-juggling-javascript-other-languages`](../type-juggling-javascript-other-languages/SKILL.md) (1 hop)
3. **IF** the loose comparison guards a password or token check **THEN** treat it as an authentication bypass and prioritize the magic-hash and null-coercion branches
4. **IF** the attacker can control the type of a parameter (array versus string, number versus string) **THEN** model the type channel first, since coercion depends on the submitted type as much as the value
5. **IF** the value is JSON and the parser preserves booleans or numbers **THEN** test type confusion where `true` or `0` reaches a comparison expecting a string
6. **IF** the check compares a hash output with a loose operator and the algorithm is MD5 or SHA-1 **THEN** probe for a magic-hash collision that coerces to a numeric zero
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-language-specific-review`](../../../blue-team/application-security/secure-code-review-language-specific-review/SKILL.md)
8. **IF** the comparison already uses a strict operator or a constant-time hash check **THEN** STOP and classify as a verified non-finding for CWE-843

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The coerced value bypasses a login or token check | [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) | The invariant is the authentication decision, reached through coercion rather than response tampering |
| The comparison guards a password reset or recovery token | [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md) | The flaw is token equality, a recovery-flow control |
| A magic-hash collision weakens a token or session comparison | [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) | The invariant moves to token unpredictability and binding, not operator choice |
| Target matches `type-juggling-and-loose-comparison-php-juggling` | [`type-juggling-and-loose-comparison-php-juggling`](../type-juggling-and-loose-comparison-php-juggling/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `type-juggling-javascript-other-languages` | [`type-juggling-javascript-other-languages`](../type-juggling-javascript-other-languages/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the comparison and read its operator.** Find the security check (login, token, hash, access flag) and record whether it uses a loose operator or an implicit coercion such as a truthy check or a non-strict membership test versus a strict operator.
2. **Determine which operand the attacker controls and its type channel.** Identify whether the request lets you submit the operand as a different type (array, number, boolean, null) as well as a different value, because coercion depends on type.
3. **Record a strict baseline.** Submit a value that is clearly unequal and confirm the check rejects it, so a later acceptance is attributable to coercion rather than a correct match.
4. **Choose the coercion branch from the operator and types.** For numeric-string coercion test a magic-hash `0e` form; for array coercion test submitting an array where a string is expected; for boolean coercion test `true` or `0`; pick the branch the operator and type channel actually allow.
5. **Compare loose against strict at the same check.** Show the probe passes under the loose operator and would fail under a strict one, isolating the operator as the cause.
6. **Stop condition.** Halt when the probe either (a) is admitted by the loose comparison and rejected by a strict one, (b) is rejected under both, or (c) would require brute-forcing a real secret to advance. Case (a) confirms CWE-843, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single value unequal under strict equality yet equal under the loose operator at the named check, with the source line showing the loose operator, and the behavior reverting when the operator is made strict. An error or crash from a type mismatch is not proof of a bypass.
8. **Close with the structural fix.** Replace loose comparison with strict equality or a purpose-built function such as a constant-time compare, reject non-scalar types before the check, and compare canonicalized types. Verify by replaying the coercion probe against the strict build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A hash compared with a loose operator where one operand is a `0e`-prefixed digest | Proves magic-hash coercion to numeric zero on any language that coerces numeric strings |
| A login check accepting an array where a string password is expected | Proves array-versus-string confusion where the comparison yields null or false treated as a match |
| A JSON field parsed as boolean `true` reaching a string equality check | Proves type confusion across the JSON boundary on a JavaScript or Python backend |
| A security flag evaluated with a truthy check rather than strict equality | Proves coercion of `1`, the string one, or the string true to the same decision |
| Source using a loose equality or non-strict membership test in an auth path | Proves the loose operator at the code level, independent of a specific payload |
| The same value rejected by strict equality but accepted by loose equality at one endpoint | Proves the differential is the operator, not the value |
| A switch statement matching a coerced numeric case for a string input | Proves loose matching inside control flow, a less obvious coercion sink |

## Worked Contrast

**Vulnerable pattern:**

```php
<?php
// Loose comparison coerces a 0e-prefixed hash to numeric zero
function check_token($provided, $expected) {
    if (md5($provided) == $expected) {   // == not ===
        return true;
    }
    return false;
}
```

**Hardened pattern:**

```php
<?php
// Strict, constant-time comparison; no coercion, no early-exit timing leak
function check_token(string $provided, string $expected): bool {
    return hash_equals($expected, hash('sha256', $provided));
}
```

**Why this matters:** The defect compares a hash with a loose operator, so two unequal digests that both coerce to numeric zero (a magic hash) are treated as equal. The fix compares the full string with a constant-time function that neither coerces types nor exits early, so only a genuinely equal value passes.

## When It Is NOT This Issue

- **Strict operator already used:** a check using strict equality or a constant-time compare does not coerce, so a `0e` value is just an unequal string.
- **Type mismatch causing an error, not a match:** a crash or a 500 when an array is submitted is a robustness bug, not a comparison bypass.
- **Non-security comparison:** a loose comparison in display logic or sorting has no authentication or access impact and is out of scope.
- **Language that does not coerce here:** some languages return false across string and integer, so a magic hash from another language does not transfer without a real coercion path.
- **Hash not attacker-influenced:** magic-hash tricks need the attacker to control the pre-image side; a server-only hash compared loosely may still be unexploitable.
- **Input already type-constrained:** a parameter forced to a scalar string by the framework cannot be submitted as an array to trigger null coercion.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `type-juggling-and-loose-comparison` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `type-juggling-and-loose-comparison` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: type-juggling-and-loose-comparison
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-843 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`type-juggling-and-loose-comparison-php-juggling`](../type-juggling-and-loose-comparison-php-juggling/SKILL.md) - Web and Application (leaf)
- [`type-juggling-javascript-other-languages`](../type-juggling-javascript-other-languages/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `type-juggling-and-loose-comparison` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-843`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (3), CYBER_CPT/github_security_md (2), CYBER_CPT/ctf_search (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
