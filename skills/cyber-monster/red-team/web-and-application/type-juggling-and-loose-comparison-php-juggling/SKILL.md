---
name: type-juggling-and-loose-comparison-php-juggling
description: PHP type juggling exploitation. Covers loose comparison in PHP authentication, magic hashes, array and string comparison traps, and strcmp and in_array weaknesses. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["php type juggling", "php loose comparison", "magic hash php", "php == bypass"]
cwe: [CWE-843]
owasp: [A04:2021]
attack: []
capec: [CAPEC-463]
related: [type-juggling-and-loose-comparison, type-juggling-javascript-other-languages, sql-injection, cross-site-scripting]
parent: type-juggling-and-loose-comparison
---

# Type Juggling and Loose Comparison Php Juggling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

In PHP the loose equality operator and functions like `in_array`, `switch`, and `strcmp` apply juggling rules that coerce strings to numbers and treat certain forms specially. A hash string of the form `0e` followed by digits is read as scientific notation for zero, so two different `0e` MD5 or SHA-1 digests compare equal (the magic-hash class). `strcmp` returns null when handed an array instead of a string, and null loosely equals zero, so `strcmp($password, $array) == 0` passes. `in_array($needle, $haystack)` without the strict third argument coerces each element. The decision point is a PHP security check using these loose constructs on attacker-controlled types. The attacker authenticates or matches a token without the secret. Confirmation is a PHP value unequal under strict equality yet equal under the loose operator, or an array that nulls a comparison, at the check.

- **Precondition chain:** PHP code uses a loose operator, a non-strict `in_array`, a switch, or `strcmp` in a security check, the attacker controls the compared value and can submit it as a string or array, and the coerced result matches the expected value.
- **Readable differential:** Submit a `0e` magic hash or an array where a string is expected, versus a plainly wrong string; a finding exists when the PHP loose construct accepts the crafted type while the plain string is rejected, and it closes when the code switches to strict equality or a constant-time compare.
- **Empirical grounding:** CWE-843 Access of Resource Using Incompatible Type, mapped by the skill to OWASP A04:2021 and surfacing under OWASP Top 10:2025 A07:2025 Authentication Failures when the check is an auth gate. SOURCES.md has no PHP-juggling-specific advisory, so grounding stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the check compares MD5 or SHA-1 output with a loose operator **THEN** probe the `0e` magic-hash class where two digests coerce to numeric zero
2. **IF** the check calls `strcmp($input, $stored)` **THEN** submit `input` as an array so `strcmp` returns null and the `== 0` test passes
3. **IF** the check uses `in_array($x, $list)` without the strict flag **THEN** test coercion of `0`, the string zero, or `true` against the list elements
4. **IF** the decision is a switch on a user string **THEN** test a numeric case that a coerced string falls into
5. **IF** the target profile is not yet confirmed as PHP **THEN** start at parent class [`type-juggling-and-loose-comparison`](../type-juggling-and-loose-comparison/SKILL.md) (1 hop)
6. **IF** the language is JavaScript, Python, or Ruby **THEN** switch to [`type-juggling-javascript-other-languages`](../type-juggling-javascript-other-languages/SKILL.md) (1 hop)
7. **IF** the comparison already uses strict equality, a constant-time compare, or a strict `in_array` **THEN** record a type-safe check and do not report a finding
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-language-specific-review`](../../../blue-team/application-security/secure-code-review-language-specific-review/SKILL.md)
9. **IF** the parameter cannot be submitted as an array and no `0e` string reaches a loose compare **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The coerced value grants a login without credentials | [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) | The invariant is the credential check, reached via juggling |
| Array submission nulls a comparison through PHP parameter handling | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | The channel is the array type binding, a request-shaping concern |
| The loose check sits inside a PHP framework such as Laravel | [`cms-and-framework-exploitation-php-and-laravel`](../cms-and-framework-exploitation-php-and-laravel/SKILL.md) | The surrounding framework idioms change where the comparison lives |
| Need parent class methodology | [`type-juggling-and-loose-comparison`](../type-juggling-and-loose-comparison/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the PHP comparison construct.** Grep for loose equality, `in_array(` without a third argument, `switch (`, and `strcmp` or `strcasecmp` in authentication, token, and authorization code.
2. **Determine the type channel.** Check whether the parameter can arrive as an array via `name[]=` or as a numeric-looking string, since `strcmp` with an array returns null and numeric strings trigger the `0e` rule.
3. **Record a strict baseline.** Send a plainly wrong scalar string and confirm rejection, so an accepted crafted type is attributable to juggling.
4. **Pick the PHP coercion branch.** For hash checks send a known `0e`-coercing preimage; for `strcmp` send the parameter as an array; for non-strict `in_array` send `0` or `true`; for a switch send a value that coerces into a numeric case.
5. **Confirm loose-versus-strict at the check.** Demonstrate acceptance under the current operator and rejection were it strict equality, a constant-time compare, or a strict `in_array`.
6. **Stop condition.** Halt when the crafted type is either (a) accepted by the loose construct and would be rejected by a strict one, (b) rejected regardless, or (c) only reachable by brute-forcing a real secret. Case (a) confirms CWE-843 in PHP, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the crafted value or type accepted at the named PHP construct while a strict comparison would reject it, with the source line, reverting when made strict. A PHP array-to-string conversion warning alone is not a bypass.
8. **Close with the structural fix.** Use strict equality, a constant-time function for secret comparison, a strict `in_array`, cast or reject non-scalar input before the check, and avoid `strcmp` on untrusted types. Verify by replaying the array and `0e` probes against the hardened code.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `md5($in) == $stored` where `$stored` is a `0e` digest | Proves the PHP magic-hash class coercing both sides to float zero |
| `strcmp($password, $input) == 0` with `$input` submitted as an array | Proves the PHP strcmp-returns-null bypass where null loosely equals zero and passes the check |
| `in_array($role, $allowed)` without the strict third argument | Proves loose membership coercion on the PHP stack |
| A switch on user input matching a numeric case for a coerced string | Proves loose control-flow coercion in a PHP switch statement reaching a privileged branch |
| A request parameter accepted as `name[]=` by the PHP handler | Proves the array type channel needed for the strcmp and null branches |
| Source comparing secrets with a loose operator rather than a constant-time function | Proves both a juggling risk and a timing-comparison weakness in PHP |
| A `0e`-prefixed value accepted where a random string is rejected | Proves the differential is PHP numeric-string coercion, not the value |

## Worked Contrast

**Vulnerable pattern:**

```php
<?php
// strcmp returns NULL when $_POST['pw'] is an array; NULL == 0 is true
function login($stored_hash) {
    $pw = $_POST['pw'];
    if (strcmp($pw, $stored_hash) == 0) {   // loose == plus strcmp misuse
        return true;
    }
    return false;
}
```

**Hardened pattern:**

```php
<?php
// Reject non-string input, then compare in constant time with no coercion
function login(string $stored_hash): bool {
    $pw = $_POST['pw'] ?? '';
    if (!is_string($pw)) {
        return false;
    }
    return hash_equals($stored_hash, hash('sha256', $pw));
}
```

**Why this matters:** The defect lets `pw` arrive as an array, so `strcmp` returns null and the null-equals-zero test passes without any password. The fix rejects non-string input and uses a strict constant-time comparison with no coercion, so only the correct value authenticates.

## When It Is NOT This Issue

- **Strict comparison in place:** strict equality or a constant-time compare does not juggle, so `0e` strings and arrays are simply unequal.
- **Strict membership flag:** a strict `in_array` disables element coercion, closing the loose-membership path.
- **Array submission rejected upstream:** a framework that casts `pw` to string before the check removes the strcmp-null branch.
- **Warning without acceptance:** an array-to-string conversion notice that still results in rejection is not a bypass.
- **Hash not under attacker control:** magic-hash tricks require control of the pre-image; a server-generated nonce compared loosely may be safe.
- **Non-auth comparison:** a loose comparison in unrelated business display logic has no security impact.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `type-juggling-and-loose-comparison-php-juggling` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `type-juggling-and-loose-comparison-php-juggling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: type-juggling-and-loose-comparison-php-juggling
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-843 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`type-juggling-and-loose-comparison`](../type-juggling-and-loose-comparison/SKILL.md) - Web and Application (leaf)
- [`type-juggling-javascript-other-languages`](../type-juggling-javascript-other-languages/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `type-juggling-and-loose-comparison-php-juggling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-843`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 7 |
| Top sources | SecEval/owasp_wstg (1), CYBER_CPT/github_security_md (1), CYBER_CPT/pentesterlab (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
