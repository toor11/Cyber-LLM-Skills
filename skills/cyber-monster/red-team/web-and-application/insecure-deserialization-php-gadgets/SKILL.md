---
name: insecure-deserialization-php-gadgets
description: PHP deserialization and POP chains. Covers PHP object injection, magic method chains, phpggc gadget selection per framework, and phar metadata deserialization. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["php deserialization", "php object injection", "pop chain", "phpggc", "phar metadata"]
cwe: [CWE-502]
owasp: [A08:2021]
attack: [T1059]
capec: [CAPEC-586]
related: [insecure-deserialization, insecure-deserialization-java-gadgets, insecure-deserialization-python-and-ruby-gadgets, insecure-deserialization-dotnet-gadgets]
parent: insecure-deserialization
---

# Insecure Deserialization Php Gadgets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)

## Mechanism and Preconditions

A PHP application calls unserialize() on attacker-controlled text (a cookie, a POST field, or phar:// stream metadata), which rebuilds PHP objects and invokes their magic methods, so __wakeup and __destruct fire on classes the attacker chose. A property-oriented programming (POP) chain strings these magic methods together until a property under attacker control reaches a dangerous call such as a file write, an SQL query, or a callback invocation. The decision point is whether unserialize is allowed to instantiate arbitrary classes at all; the allowed_classes option is the structural switch. The attacker gains code execution or file operations in the web-server context. A non-destructive check uses a whitelisted class with a benign side effect, or confirms that a phar stream wrapper reaches the sink, without running a weaponized chain.

- **Precondition chain:** An attacker-controlled string reaches unserialize() or a phar:// stream-metadata read, the application defines classes with exploitable magic methods, and allowed_classes is not set to false.
- **Readable differential:** The same field carrying a benign scalar versus an O:n:"Class" object string: the object form instantiates a class and triggers its magic method, and that behavior vanishes once unserialize is called with allowed_classes set to false or replaced by json_decode.
- **Empirical grounding:** CWE-502 under OWASP Top 10:2025 A08 Software or Data Integrity Failures. CVE-2025-13081 (Drupal core gadget chain, SA-CORE-2025-006) is a 2025 PHP object-injection instance fixed across the 10.4, 10.5, 11.1, and 11.2 branches.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the class profile is not yet confirmed as PHP object injection **THEN** start at the parent class [`insecure-deserialization`](../insecure-deserialization/SKILL.md) (1 hop)
2. **IF** an O:n:"Class" string reaches unserialize() from a cookie or POST field **THEN** treat the unserialize call as the sink and map magic methods on reachable classes
3. **IF** the stream is Java serialization, not a PHP object string **THEN** switch to [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) (1 hop)
4. **IF** the input is a pickle stream or Ruby Marshal blob **THEN** switch to [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) (1 hop)
5. **IF** a file metadata function such as file_exists or getimagesize receives a phar:// path **THEN** treat phar metadata deserialization as the trigger and locate the controllable path
6. **IF** a known framework (Laravel, WordPress, vBulletin, TYPO3) is installed **THEN** inventory its POP chains with phpggc -l before asserting reachability
7. **IF** the sink is eval(), assert(), or create_function on request data **THEN** reclassify as code evaluation rather than object injection
8. **IF** the magic-method chain terminates in a string-built SQL query **THEN** treat the SQL layer as a second-order sink
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md)
10. **IF** input is routed through json_decode or unserialize with allowed_classes set to false **THEN** STOP and record a verified non-finding because no object graph can form

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The sink is eval() or create_function rather than unserialize() | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | Invariant is direct code evaluation, not object-graph instantiation |
| Object injection reaches an SQL layer through a wakeup method | [`sql-injection`](../sql-injection/SKILL.md) | The downstream sink is SQL lexical parsing, a different interpreter boundary |
| Need parent class methodology | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the unserialize call and its input source.** Trace request text (cookie, POST body, query value) or a phar:// path into unserialize or a stream-metadata-triggering function. The magic-method entry point, not the controller, is the sink.
2. **Classify whether class instantiation is open.** Check the unserialize call for an allowed_classes option. An unserialize without it, or a phar wrapper reachable from input, is the candidate; allowed_classes set to false closes the branch.
3. **Map the POP chain surface.** List classes that define __wakeup, __destruct, __toString, or __call with a reachable side effect, and whether a framework (Laravel, WordPress, vBulletin) supplies a prebuilt chain visible in phpggc -l.
4. **Record a benign baseline.** Submit a scalar or a whitelisted object string with no gadget effect and capture the response shape. This is the control.
5. **Send an object-instantiation differential.** Submit an O:n:"Class" string for a class with a benign observable side effect, or point a metadata function at a benign phar path, and compare against the baseline. A change proves unserialize instantiates the object.
6. **Stop condition.** Halt when the probe (a) demonstrates object instantiation that stops once allowed_classes is false, (b) shows no instantiation across two baselines, or (c) would require firing a destructive terminal gadget. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign magic-method side effect tied to the object string, the unserialize source line reached by request data, and the absence of allowed_classes. An unserialize() offset error alone is not proof.
8. **Close with the structural fix and verify.** Replace native unserialize with json_decode for data, or set unserialize($raw, ['allowed_classes' => false]) where the format is fixed, and disable the phar wrapper where not needed, then replay the object string to confirm no class is reconstructed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A cookie or POST value shaped like O:8:"stdClass": entering unserialize() | Proves a PHP object string reaches the deserializer, the entry condition for a POP chain on a PHP stack |
| A class defining __wakeup, __destruct, or __toString with a sensitive side effect | Proves a magic-method gadget exists whose invocation during unserialize can start a chain |
| unserialize() called without an allowed_classes option on request data | Proves arbitrary class instantiation is permitted, the structural defect that makes object injection possible |
| A file_exists, getimagesize, or fopen call receiving a phar:// path from input | Proves the phar stream wrapper can trigger metadata deserialization without an explicit unserialize call |
| phpggc lists a known POP chain for the installed framework version | Proves a prebuilt gadget chain exists for Laravel, WordPress, or vBulletin, raising reachability |
| An unserialize(): Error at offset entry in the PHP error log tied to request input | Proves the deserializer is parsing attacker bytes even when the chain is malformed |
| The decoded value survives as __PHP_Incomplete_Class with no live methods | Proves allowed_classes set to false is in effect, which is a working control rather than a finding |

## Worked Contrast

**Vulnerable pattern:**

```php
<?php
// Cookie value is unserialized, firing __wakeup/__destruct on any class
$prefs = unserialize($_COOKIE['prefs']);
return render($prefs);
```

**Hardened pattern:**

```php
<?php
// No object instantiation: data stays scalar/array, so a POP chain cannot start
$prefs = json_decode($_COOKIE['prefs'], true);
if (!is_array($prefs)) {
    throw new InvalidArgumentException('bad prefs');
}
return render($prefs);
// If native serialization is unavoidable: unserialize($raw, ['allowed_classes' => false]);
```

**Why this matters:** json_decode (or unserialize with allowed_classes set to false) reconstructs only scalars and arrays, never a PHP object graph, so no magic-method gadget chain can begin. The decision shifts from the cookie bytes to a format that cannot instantiate classes.

## When It Is NOT This Issue

- **unserialize with allowed_classes set to false:** request data is deserialized but no object is ever instantiated, so magic methods cannot fire.
- **json_decode mistaken for unserialize:** a serialized-looking string passed to json_decode stays scalar or array and starts no POP chain.
- **Magic methods with no exploitable side effect:** a class defines __wakeup but it only sets a property, so the chain has no dangerous terminal gadget.
- **phar path not reachable by a metadata function:** a phar:// string that never reaches file_exists, getimagesize, or a similar call does not trigger metadata deserialization.
- **Object string from a trusted internal cache:** a serialized value produced and stored server-side, never attacker-influenced, is not object injection.
- **__PHP_Incomplete_Class result:** the decoded value lacks live methods because class loading is restricted, so no gadget executes.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `insecure-deserialization-php-gadgets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `insecure-deserialization-php-gadgets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: insecure-deserialization-php-gadgets
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-502 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) - Blue Detection/Defense Counterpart
- [`insecure-deserialization`](../insecure-deserialization/SKILL.md) - Web and Application (core)
- [`insecure-deserialization-java-gadgets`](../insecure-deserialization-java-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) - Web and Application (leaf)
- [`insecure-deserialization-dotnet-gadgets`](../insecure-deserialization-dotnet-gadgets/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `insecure-deserialization-php-gadgets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-502, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 24 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (11), bugbounty-hunter-v1 (3), CYBER_CPT/oxdf (3), CYBER_CPT/nuclei_templates (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
