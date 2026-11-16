---
name: ssti-java-template-engines
description: Java template engine injection. Covers Freemarker, Velocity, Pebble and Thymeleaf injection, including builtin execution paths and Spring expression reachability. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["freemarker ssti", "velocity ssti", "pebble ssti", "thymeleaf ssti", "java template"]
cwe: [CWE-1336, CWE-94]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [ssti, ssti-jinja2-and-twig, ssti-sandbox-escape, ssti-node-and-client-engines]
parent: ssti
---

# SSTI Java Template Engines - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Java template engines evaluate expression languages, so injecting into the template source reaches the JVM object graph. Freemarker evaluates `${ }` and directives like `<#assign>`, and its `?new` builtin or an unrestricted `TemplateClassResolver` can instantiate classes; Velocity evaluates `#set` and dollar references; Thymeleaf evaluates `${ }`, `*{ }`, and `#{ }` backed by Spring EL, where `T(java.lang.Runtime)` names a class directly. The Thymeleaf research on versions up to 3.1.3 shows a context object reached through `th:with` and `#ctx` handing control to the TemplateManager so one evaluation triggers another, stepping around the expression sandbox. The invariant is that template content and SpEL fragments must never be assembled from request data; the engine sandbox narrows which classes are reachable but does not remove the consequence.

- **Precondition chain:** Request data is concatenated into a Java template or a SpEL fragment, the engine such as Freemarker, Velocity, Pebble, or Thymeleaf evaluates it, and the rendered output or a side effect shows the expression ran.
- **Readable differential:** An engine-specific arithmetic or assignment probe versus inert text; a finding exists when the Java engine computes the expression while the control renders the literal, and it closes when input is passed only as a model attribute into a fixed template in text mode.
- **Empirical grounding:** CWE-1336 and CWE-94 under OWASP A03:2021 Injection; the Thymeleaf sandbox research on versions up to 3.1.3 shows `th:with` and `#ctx` reaching the TemplateManager so one evaluation triggers another, confirming that the expression sandbox reduces but does not remove the consequence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a Java engine **THEN** start at the parent class [`ssti`](../ssti/SKILL.md) first (1 hop)
2. **IF** the engine is Freemarker with `${ }` and `<#assign>` **THEN** probe assignment and arithmetic before considering `?new` or the class resolver
3. **IF** the engine is Velocity with `#set` and dollar references **THEN** use a `#set` assignment probe to confirm evaluation
4. **IF** the engine is Thymeleaf backed by Spring EL **THEN** treat `${ }` and `*{ }` as SpEL and check whether `#ctx` reaches the TemplateManager
5. **IF** a Jinja2 or Twig engine is actually in use **THEN** switch to [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) (1 hop)
6. **IF** an expression sandbox is present and must be escaped **THEN** switch to [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) (1 hop)
7. **IF** the SpEL is evaluated outside any template **THEN** read [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) for the expression-language path
8. **IF** the input is reflected but not evaluated **THEN** reclassify as [`cross-site-scripting`](../cross-site-scripting/SKILL.md)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** no engine delimiter evaluates after testing each **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Engine is Jinja2 or Twig | [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) | Different delimiter family and object graph |
| SpEL evaluated outside a template | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | The sink is an expression evaluator, not the template manager |
| A sandbox must be escaped step by step | [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) | The invariant shifts to sandbox reachability |
| Need parent class methodology | [`ssti`](../ssti/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the Java template or SpEL assembly point.** Separate a model attribute rendered by a fixed Freemarker, Velocity, Pebble, or Thymeleaf template, which is safe, from request data concatenated into the template text or a SpEL expression string, which is the sink.
2. **Confirm evaluation with an engine-correct probe.** Use `${7*7}` or `<#assign x=7*7>` for Freemarker, a `#set` assignment for Velocity, and a `${ }` SpEL expression for Thymeleaf; a computed result proves the JVM evaluated the expression.
3. **Fingerprint the engine precisely.** Directives differ: `<#...>` is Freemarker, `#set` and dollar references are Velocity, and `*{ }` and `#{ }` are Thymeleaf. The directive that fires selects the builtin and resolver vocabulary.
4. **Record a paired baseline.** Compare the evaluating probe against the same text with the delimiter neutralised, so the differential is JVM evaluation and not reflection.
5. **Weigh the sandbox and its known escapes.** For Thymeleaf up to 3.1.3 check whether `th:with` and `#ctx` can reach the TemplateManager so one evaluation triggers another, and for Freemarker whether `TemplateClassResolver` is unrestricted. Sandbox presence narrows but does not close the finding.
6. **Stop condition.** Halt when a probe computes an expression that reverts to literal when input is bound as a model attribute, or returns only the literal across engines, or would require reaching `Runtime` or the class resolver to run a command. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is an engine-specific expression evaluated by the JVM on an identical request, plus the source line that concatenates input into the template or SpEL string. A literal `${7*7}` that renders unchanged, or a reflected payload, is not proof.
8. **Close with the structural fix.** Render fixed templates in text mode with request data as model attributes only, disable dangerous builtins and restrict `TemplateClassResolver`, and never build a SpEL fragment from input, keeping the engine sandbox as defence in depth. Verify by re-running the engine-specific probe against the patched template.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `<#assign>` or `${ }` computing in a Freemarker response | Proves Freemarker evaluated the expression on a Java stack, where `?new` or the class resolver may follow |
| A `#set` assignment returning 49 in Velocity | Proves Velocity directive evaluation on a Java stack, identifying the engine by its reference syntax |
| A Thymeleaf `${ }` or `*{ }` SpEL expression evaluating | Proves Spring EL backs the template, so class names like `T(...)` are in reach |
| `#ctx` and `th:with` reaching the TemplateManager | Proves the Thymeleaf sandbox escape where one evaluation triggers another, per the 3.1.3 research |
| An unrestricted `TemplateClassResolver` in Freemarker config | Proves the Freemarker sandbox is not constraining class instantiation on this deployment |
| `T(java.lang.Runtime)` resolvable from a template expression | Proves SpEL class access from the template, the gateway to command execution on a Java stack |
| The same `${ }` rendered literally when passed as a model attribute | Proves the non-evaluating control, separating evaluation from reflection |

## Worked Contrast

**Vulnerable pattern:**

```java
// Template source built from request data, then evaluated by Freemarker
public String render(HttpServletRequest req, Configuration cfg) throws Exception {
    String name = req.getParameter("name");
    String src = "Hello ${" + name + "}";
    Template t = new Template("inline", new StringReader(src), cfg);
    StringWriter out = new StringWriter();
    t.process(Collections.emptyMap(), out);
    return out.toString();
}
```

**Hardened pattern:**

```java
// Fixed template file; request data is a model attribute, never part of the template source
public String render(HttpServletRequest req, Configuration cfg) throws Exception {
    String name = req.getParameter("name");
    cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
    Template t = cfg.getTemplate("greet.ftl");
    StringWriter out = new StringWriter();
    t.process(Collections.singletonMap("name", name), out);
    return out.toString();
}
```

**Why this matters:** The defect concatenates request data into the Freemarker template text, so attacker-supplied `${ }` expressions are evaluated against the model. The fix loads a fixed template, passes the value as a bound model attribute, and installs ALLOWS_NOTHING_RESOLVER so even a reached expression cannot instantiate classes, keeping the sandbox as defence in depth rather than the primary control.

## When It Is NOT This Issue

- **Literal brace rendered unchanged:** a dollar-brace sequence returned verbatim means the engine did not evaluate that position.
- **Model attribute, not template source:** a value bound into a fixed template is auto-escaped and never compiled as an expression.
- **Restricted class resolver:** a Freemarker ALLOWS_NOTHING_RESOLVER stops `?new` from instantiating classes, so arithmetic evaluation alone is lower impact.
- **Reflected input, no evaluation:** a payload echoed without computation is XSS, not Java SSTI.
- **SpEL in a non-template sink:** an expression evaluated by a SpEL parser outside templating belongs to code-injection.
- **Patched Thymeleaf:** a version past the 3.1.3 sandbox research where #ctx no longer reaches the TemplateManager changes the escape conclusion.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssti-java-template-engines` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssti-java-template-engines` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssti-java-template-engines
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1336, CWE-94 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssti`](../ssti/SKILL.md) - Web and Application (core)
- [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) - Web and Application (leaf)
- [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) - Web and Application (leaf)
- [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssti-java-template-engines` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1336, CWE-94, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/govuln (2), CYBER_CPT/go_exploitdb (2), CYBER_CPT/github_security_md (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
