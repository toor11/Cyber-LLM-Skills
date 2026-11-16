---
name: code-injection-and-eval-expression-language
description: Expression language injection. Covers SpEL, OGNL, MVEL and Spring EL injection in Java applications, from arithmetic confirmation to Runtime execution. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["expression language injection", "spel injection", "ognl injection", "mvel"]
cwe: [CWE-94, CWE-95]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-242]
related: [code-injection-and-eval, code-injection-and-eval-dynamic-language-eval, sql-injection, cross-site-scripting]
parent: code-injection-and-eval
---

# Code Injection and Eval Expression Language - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A Java application feeds a request value into an expression-language parser such as Spring SpEL, Struts/OGNL, MVEL, or a Jakarta EL evaluator, and the parser resolves the text against an evaluation context that exposes live object graphs and type references. When that context is a full StandardEvaluationContext, the expression can reach T(java.lang.Runtime) and reflective type access, turning a template or rule string into JVM method invocation. The security decision is the choice of evaluation context and whether user text is parsed as an expression at all, not a character filter. Verification begins with a delimiter and arithmetic probe so a reflected 49 identifies both that an EL is active and which dialect owns the delimiter, before any type reference is touched.

- **Precondition chain:** A request value is parsed as an expression by SpEL, OGNL, MVEL, or Jakarta EL, the evaluation context grants type or method access rather than read-only data binding, the parser actually evaluates the expression during the request, and a computed value or type error is observable.
- **Readable differential:** The same field carrying a plain literal versus carrying a dialect-delimited arithmetic expression; a finding exists when the computed result appears for the expression form, and it stops once the evaluator is switched to a read-only, data-only context or the user text is no longer parsed as an expression.
- **Empirical grounding:** CWE-917 expression language injection within CWE-94 and OWASP A05:2025 Injection anchors this; SOURCES records the EL sandbox-escape class through GHSA-cpwx-vrp4-4pq7 (Jinja2 |attr reaching str.format) and the Thymeleaf 3.1.3 sandbox bypass via th:with and #ctx, both template-expression breakouts of the same family.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a JVM expression-language sink **THEN** start at the parent class [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) for general triage
2. **IF** the sink is a scripting-language eval in PHP, Python, Ruby, or Node **THEN** switch to [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) (1 hop)
3. **IF** the delimiter and context point to a template engine like Twig or Freemarker **THEN** reclassify as template execution and read [`ssti`](../ssti/SKILL.md)
4. **IF** the expression is resolved through a JNDI lookup string **THEN** treat it as naming-service resolution and read [`jndi-injection`](../jndi-injection/SKILL.md)
5. **IF** a `${...}` delimiter reflects but no computation occurs **THEN** classify the delimiter dialect before assuming EL is active
6. **IF** the value is deserialized into an object graph rather than parsed as EL **THEN** reclassify as gadget reconstruction and read [`insecure-deserialization`](../insecure-deserialization/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no delimiter produces a computed value across baselines **THEN** STOP and record a verified non-finding for this variant

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Sink is a scripting-language interpreter eval | [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) | Routes to an interpreter eval rather than a JVM expression grammar |
| Delimiter and context indicate a template engine | [`ssti`](../ssti/SKILL.md) | Invariant is template sandbox escape, overlapping but distinct from raw EL |
| Expression is resolved via a JNDI lookup | [`jndi-injection`](../jndi-injection/SKILL.md) | Invariant is naming-service resolution of an attacker-controlled URI |
| Need parent class methodology | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the EL engine and its evaluation context.** Determine whether the parser is SpEL, OGNL, MVEL, or Jakarta EL and whether it runs with a StandardEvaluationContext or a SimpleEvaluationContext, because the context, not the input, decides reach.
2. **Trace the request field into the parseExpression call.** Follow the parameter to where the string becomes an Expression object, noting whether a template parser mode or a raw expression mode is used.
3. **Select a delimiter-and-arithmetic oracle.** Use the dialect delimiters as the oracle: a reflected computed value names the engine with the least intrusive probe, before any type reference.
4. **Record a literal baseline.** Send a plain name twice and capture the rendered output so the arithmetic result stands out against ordinary reflection.
5. **Apply the dialect delimiter differential.** Submit the same value wrapped in each dialect delimiter and compare; the delimiter that returns the computed value selects the active engine from evidence rather than assumption.
6. **Stop condition.** Halt when the probe either (a) returns the computed value and reverts under a read-only data-only context, (b) shows no computation for any delimiter across baselines, or (c) would require a T(java.lang.Runtime) or reflective method call to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is one literal swapped for one delimited arithmetic expression returning its computed value, plus the source line calling parseExpression with request input and a type-granting context. A reflected delimiter with no computation is not proof.
8. **Close with the structural fix and verify.** Switch to SimpleEvaluationContext.forReadOnlyDataBinding, or map a template id to a server-owned expression so user text is never parsed, then replay the delimiter differential and confirm no computed value returns.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `new SpelExpressionParser().parseExpression(userInput)` with a StandardEvaluationContext | Proves a Spring SpEL sink where the context exposes type references and method invocation |
| An OGNL expression reaching `@java.lang.Runtime@getRuntime` | Proves a Struts or OGNL context granting static method access through the type resolver |
| A `${...}` or `#{...}` delimiter returning a computed arithmetic value | Proves a Jakarta EL or SpEL evaluator is active and names the delimiter dialect in use |
| A `%{7*7}` fragment resolving to 49 in a response field | Proves an OGNL value-stack evaluation typical of Struts tag and parameter handling |
| MVEL template output computing an injected expression | Proves an MVEL sink where property and method resolution run against the supplied context |
| A type-reference token raising a SpEL EvaluationException | Proves the parser compiled the expression, distinguishing EL evaluation from plain reflection |

## Worked Contrast

**Vulnerable pattern:**

```java
// Spring SpEL: user text parsed and evaluated against a full context
public Object greet(String userInput, Order order) {
    Expression exp = new SpelExpressionParser().parseExpression(userInput);
    return exp.getValue(new StandardEvaluationContext(order));
}
```

**Hardened pattern:**

```java
// Evaluate only a server-owned expression against a read-only, data-only context
private static final Map<String, Expression> TEMPLATES = loadApprovedExpressions();

public Object greet(String templateId, Order order) {
    Expression exp = TEMPLATES.get(templateId);
    if (exp == null) {
        throw new IllegalArgumentException("unknown template id");
    }
    EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    return exp.getValue(ctx, order);
}
```

**Why this matters:** The vulnerable method parses attacker text as SpEL against a StandardEvaluationContext, which exposes type references and Runtime. The fix never parses user input: a caller supplies only a template id that maps to a pre-approved expression, evaluated against a read-only data-binding context that cannot resolve types or invoke arbitrary methods.

## When It Is NOT This Issue

- **Read-only data binding already set:** a SpEL call using SimpleEvaluationContext.forReadOnlyDataBinding cannot reach types or methods, so a reflected delimiter is not exploitable.
- **Delimiter reflected but not parsed:** a `${...}` string echoed verbatim because the field is plain text, with no computed value, is HTML reflection rather than EL injection.
- **Server-owned expressions only:** a template id mapped to a fixed, developer-authored expression never parses user text and is safe even though an evaluator runs.
- **Template engine misread as EL:** a Twig or Freemarker `{{ }}` sink belongs to the SSTI skill with its own sandbox invariant.
- **Compile error without computation:** an EvaluationException from malformed input proves parsing attempts, not that a type-granting context resolved the expression.
- **Caller-only evaluation scope:** an expression affecting only the caller's own view with no cross-tenant or JVM reach is not reportable here.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `code-injection-and-eval-expression-language` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `code-injection-and-eval-expression-language` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: code-injection-and-eval-expression-language
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-94, CWE-95 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) - Web and Application (leaf)
- [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `code-injection-and-eval-expression-language` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, CWE-95, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (9), CYBER_CPT/github_security_md (2), CYBER_CPT/expku (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
