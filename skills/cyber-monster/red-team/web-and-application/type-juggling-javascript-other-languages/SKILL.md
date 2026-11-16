---
name: type-juggling-javascript-other-languages
description: Type coercion flaws beyond PHP. Covers JavaScript coercion, Python and Ruby comparison traps, and numeric string handling in tokens and identifiers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["javascript type coercion", "python comparison bypass", "ruby type juggling"]
cwe: [CWE-843]
owasp: [A04:2021]
attack: []
capec: [CAPEC-463]
related: [type-juggling-and-loose-comparison, type-juggling-and-loose-comparison-php-juggling, sql-injection, cross-site-scripting]
parent: type-juggling-and-loose-comparison
---

# Type Juggling and Loose Comparison Javascript and Other Languages - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Beyond PHP, dynamic languages coerce in their own ways. JavaScript loose equality applies the abstract equality algorithm, so `[]==![]` is true, the empty string equals zero, and `'0e1'` equals zero, which matters when a token or role is checked loosely or when `parseInt` and `Number` silently coerce request strings. Ruby and Python have narrower coercion but still trip on nil or None handling, `to_i` parsing, and JSON boundaries where `true`, `0`, or an array arrives where a string was expected. The decision point is a non-strict comparison or an implicit coercion in a security check reached by typed input, often JSON. The attacker makes an unequal value compare equal or makes a parser read a different type than validation assumed. Confirmation is a value unequal under strict comparison yet accepted by the loose check.

- **Precondition chain:** A JavaScript, Python, or Ruby security check uses loose equality or implicit coercion, the attacker can control the operand type through JSON or query parsing, and the coerced forms match.
- **Readable differential:** Submit a non-string type (boolean, number, array, null) or a coercing string through JSON versus a plainly wrong string; a finding exists when the loose check accepts the typed form while strict comparison rejects, and it closes when the check uses strict equality and type validation.
- **Empirical grounding:** CWE-843 Access of Resource Using Incompatible Type, under OWASP Top 10:2025 A07:2025 Authentication Failures for coerced auth checks and A06:2025 Insecure Design more broadly; the skill maps it to A04:2021. SOURCES.md lists nothing specific to JavaScript, Python, or Ruby coercion, so this entry stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the comparison is JavaScript loose equality **THEN** test abstract-equality quirks such as `[]==![]`, the empty string against zero, and `'0e1'` against zero at the check
2. **IF** the code uses `parseInt` or `Number` on a request value **THEN** probe trailing-garbage and empty-string coercion where validation assumed a clean integer
3. **IF** the input arrives as JSON **THEN** submit booleans, numbers, arrays, or null where a string is expected and watch the comparison outcome
4. **IF** the backend is Python using a truthy check or cross-type equality **THEN** test None, `0`, and the empty list reaching the decision
5. **IF** the backend is Ruby using `to_i` or loose equality **THEN** test nil and numeric parsing where a token comparison expects a string
6. **IF** the target profile is not yet confirmed or the language is PHP **THEN** start at parent class [`type-juggling-and-loose-comparison`](../type-juggling-and-loose-comparison/SKILL.md) (1 hop) or switch to [`type-juggling-and-loose-comparison-php-juggling`](../type-juggling-and-loose-comparison-php-juggling/SKILL.md) (1 hop)
7. **IF** the comparison uses strict equality with validated types **THEN** record a type-safe check and do not report a finding
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-language-specific-review`](../../../blue-team/application-security/secure-code-review-language-specific-review/SKILL.md)
9. **IF** the framework coerces every field to a validated string before the check **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A JSON boolean or object merges into state via the body parser | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | The invariant is which fields and types bind, not the comparison operator |
| A JSON object with prototype keys reaches an unsafe merge | [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) | The flaw becomes prototype chain mutation rather than value coercion |
| The typed value defeats a login decision | [`authentication-bypass-response-manipulation`](../authentication-bypass-response-manipulation/SKILL.md) | The invariant is the auth outcome reached through coercion |
| Need parent class methodology | [`type-juggling-and-loose-comparison`](../type-juggling-and-loose-comparison/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the comparison or coercion in the runtime.** Locate JavaScript loose equality, `parseInt`, `Number`, or `+`, Python truthy or cross-type equality, or Ruby `to_i` or loose equality inside a security check.
2. **Map the type channel, especially JSON.** Determine whether the client can send the field as a boolean, number, array, or null, which JSON preserves, rather than only a string.
3. **Record a strict baseline.** Submit a clearly wrong string and confirm rejection, so a later accepted typed value is attributable to coercion.
4. **Choose the language-specific branch.** For JavaScript test abstract-equality edge cases and silent `parseInt` coercion; for Python test None, zero, and empty-collection truthiness; for Ruby test nil and `to_i` parsing; pick what the parser and operator allow.
5. **Compare loose against strict at the check.** Show the typed value passes under loose equality or coercion and would fail under strict equality with type validation.
6. **Stop condition.** Halt when the typed value is (a) accepted loosely and rejected strictly, (b) rejected both ways, or (c) only reachable by brute-forcing a secret. Case (a) confirms CWE-843, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a typed value unequal under strict comparison yet accepted at the named check, with the source operator and the JSON type shown, reverting under strict equality and type validation. A NaN or parse error alone is not a bypass.
8. **Close with the structural fix.** Use strict equality, validate and coerce types at the trust boundary with a schema, reject unexpected JSON types, and parse integers with explicit radix and full-string checks. Verify by replaying the typed probe against the schema-validated build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A JavaScript check using loose equality where `[]==![]` or the empty-string-equals-zero quirk holds | Proves abstract-equality coercion on the Node or browser stack |
| `parseInt(req.query.n)` accepting a string with trailing letters as a number | Proves silent numeric coercion that bypasses a range or format check in JavaScript |
| A JSON boolean true accepted where a string role was expected | Proves cross-type confusion at the JSON boundary on a Node or Python backend |
| A Python truthy check admitting a non-empty list or object | Proves truthiness coercion instead of strict equality in Python |
| A Ruby comparison using `to_i` turning a non-numeric string into zero | Proves Ruby numeric parsing coercion at the check |
| Source using loose equality instead of strict equality in an auth path | Proves the loose operator at the code level in JavaScript |
| A field accepted as both a string and a JSON array by the same handler | Proves the type channel coercion needs, independent of value |

## Worked Contrast

**Vulnerable pattern:**

```javascript
app.post("/promote", (req, res) => {
  // Loose == plus trusting the JSON type: true == 1 and "1" == 1 all pass
  if (req.body.isAdmin == 1) {
    user.role = "admin";
  }
  res.json({ role: user.role });
});
```

**Hardened pattern:**

```javascript
app.post("/promote", (req, res) => {
  // Validate the type, then compare strictly; only a real boolean true passes
  if (typeof req.body.isAdmin !== "boolean") {
    return res.status(400).json({ error: "isAdmin must be boolean" });
  }
  if (req.body.isAdmin === true && requesterMayGrantAdmin(req.user)) {
    user.role = "admin";
  }
  res.json({ role: user.role });
});
```

**Why this matters:** The defect uses loose equality against a JSON field, so a number, a numeric string, and a boolean all coerce to the same decision and an unprivileged caller flips the role. The fix validates the field is a boolean, compares with strict equality, and still checks the caller authority, so only a genuine authorized request promotes.

## When It Is NOT This Issue

- **Strict equality already used:** strict operators do not coerce, so typed tricks fail.
- **Schema validation at the edge:** a validator that rejects non-string types removes the JSON type channel.
- **Coercion without security impact:** `parseInt` in pagination or display has no auth consequence.
- **NaN short-circuit:** a comparison that yields NaN and therefore false is not a bypass.
- **Language does not coerce the pair:** some languages treat a numeric string and an integer as unequal, so a JavaScript trick does not transfer without a real path.
- **Value re-validated server-side:** a role derived from the session rather than the body is unaffected by a coerced field.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `type-juggling-javascript-other-languages` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `type-juggling-javascript-other-languages` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: type-juggling-javascript-other-languages
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-843 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`type-juggling-and-loose-comparison`](../type-juggling-and-loose-comparison/SKILL.md) - Web and Application (leaf)
- [`type-juggling-and-loose-comparison-php-juggling`](../type-juggling-and-loose-comparison-php-juggling/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `type-juggling-javascript-other-languages` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-843`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/ctftime (3), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
