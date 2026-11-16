---
name: code-injection-and-eval-dynamic-language-eval
description: Dynamic language eval injection. Covers server-side eval in PHP, Python, Ruby and Node contexts, including sandbox escape from restricted evaluation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["eval injection php", "python eval", "ruby eval", "node eval injection"]
cwe: [CWE-94, CWE-95]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-242]
related: [code-injection-and-eval, code-injection-and-eval-expression-language, sql-injection, cross-site-scripting]
parent: code-injection-and-eval
---

# Code Injection and Eval Dynamic Language Eval - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

An interpreted-language server, PHP, Python, Ruby, or Node, passes a request string into its own runtime evaluator such as eval, exec, instance_eval, or a Function constructor, so the text is compiled into the live interpreter and runs with the application's own imports and globals. Developers often wrap the call in a restricted-globals dictionary and believe that is a sandbox; it is not, because dunder and introspection traversal from any surviving object climbs back to the import machinery. The security decision therefore lives at the eval call and its reachable object graph, not at the input filter. Verification uses a boolean or arithmetic expression whose truth value changes the response, proving the string is interpreted rather than compared as data.

- **Precondition chain:** Untrusted input reaches an interpreter eval or exec in PHP, Python, Ruby, or Node, the surrounding globals or sandbox do not actually sever introspection, the interpreter compiles and runs the expression inline, and a truth value or computed result is observable in the response or a side effect.
- **Readable differential:** A request whose expression evaluates true versus one whose expression evaluates false; a finding exists when the response body or row set tracks the boolean, and the behaviour collapses to a single outcome once the interpreter call is replaced by a structured parser over an allowed field and operator set.
- **Empirical grounding:** CWE-95 eval injection within OWASP Top 10:2025 A05:2025 Injection describes this variant; SOURCES has no interpreter-eval CVE specific to PHP, Python, Ruby, or Node, so grounding stays at the CWE and OWASP category level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a scripting-runtime eval sink **THEN** start at the parent class [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) for general triage
2. **IF** the evaluator is a JVM expression language such as SpEL, OGNL, or MVEL **THEN** switch to [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) (1 hop)
3. **IF** the eval is reached through a Mongo `$where` or a JavaScript query filter **THEN** treat it as query-layer injection and read [`nosql-injection`](../nosql-injection/SKILL.md)
4. **IF** the string flows into a template render rather than a bare eval **THEN** reclassify as template execution and read [`ssti`](../ssti/SKILL.md)
5. **IF** the sandbox relies on a restricted-globals dictionary that still exposes objects **THEN** treat the sandbox as absent and prove introspection reach non-destructively
6. **IF** the eval runs in a browser context rather than the server interpreter **THEN** reclassify as client-side and read [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the expression truth value never changes the response across baselines **THEN** STOP and record a verified non-finding for this variant

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Sink is a JVM expression evaluator | [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) | Routes to the JVM expression-grammar invariant rather than an interpreter eval |
| eval is reached via a Mongo `$where` or JS filter | [`nosql-injection`](../nosql-injection/SKILL.md) | Invariant is operator and JavaScript injection in the query layer |
| String is executed by a template engine | [`ssti`](../ssti/SKILL.md) | Invariant is template directive execution, distinct from a raw eval call |
| Need parent class methodology | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Pin the interpreter and the eval primitive.** Identify whether the runtime is PHP, Python, Ruby, or Node and which call receives the value: eval, exec, instance_eval, or a Function constructor. Each has a different introspection path back to imports.
2. **Trace the request field to the interpreter argument.** Follow the parameter through JSON decoding, type coercion, and any globals dictionary so you know exactly what the interpreter compiles.
3. **Decide whether a claimed sandbox is real.** A restricted `__builtins__` or a frozen binding is not a boundary if any passed object still answers to `__class__` or `__subclasses__`; note this before probing.
4. **Record a boolean baseline.** Send an expression that is plainly true and one plainly false, twice each, and capture the response shape so the truth-tracking signal is separated from noise.
5. **Apply the truth-value differential.** Compare the true-expression response against the false-expression response; a body or row set that follows the boolean proves interpretation, and selects this branch over a data-only comparison.
6. **Stop condition.** Stop when the probe either (a) makes the response track the expression truth value and reverts once a structured parser replaces eval, (b) yields one fixed outcome across both baselines, or (c) would require introspection into the import machinery to go further. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is one changed expression, true versus false, producing a reproducible response divergence, plus the interpreter source line passing the string to eval or exec. A reflected error about a name is not proof unless the response tracks the boolean.
8. **Close with the structural fix and verify.** Replace the interpreter call with a parser over an allowed field and operator set, or a safe literal reader such as ast.literal_eval, then replay the true and false expressions and confirm both collapse to the same safe outcome.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `eval(expr, {'__builtins__': {}}, ...)` over a request field | Proves the restricted-globals sandbox myth on Python where object introspection still reaches imports |
| `exec(` applied to a request body in a Python worker | Proves a statement-level interpreter sink that can define functions and import modules inline |
| Ruby `instance_eval` or `eval` on a parameter | Proves a Ruby metaprogramming sink that runs in the receiver's binding with full method access |
| Node `new Function(userInput)` or indirect `eval` | Proves a Node evaluator that compiles a function body with access to the module scope |
| A boolean expression whose truth value changes the row set returned | Proves the filter string is interpreted rather than compared as literal data in the interpreter |
| A restricted-eval error naming `__class__` or `__subclasses__` | Proves introspection traversal is reachable, confirming the sandbox does not sever the object graph |

## Worked Contrast

**Vulnerable pattern:**

```python
def run_filter(req, rows):
    expr = req.json["filter"]  # e.g. "row['age'] > 18"
    # restricting builtins is not a sandbox: dunder traversal still reaches imports
    return [r for r in rows if eval(expr, {"__builtins__": {}}, {"row": r})]
```

**Hardened pattern:**

```python
import operator

ALLOWED_FIELDS = {"age", "status", "country"}
_CMP = {">": operator.gt, "<": operator.lt, "==": operator.eq}

def run_filter(req, rows):
    field = req.json["field"]
    op = req.json["op"]
    value = req.json["value"]
    if field not in ALLOWED_FIELDS or op not in _CMP:
        raise ValueError("filter is outside the allowed field and operator set")
    return [r for r in rows if _CMP[op](r.get(field), value)]
```

**Why this matters:** The vulnerable version compiles a filter string with eval and trusts a restricted globals dictionary that introspection defeats. The fix removes eval and accepts only a named field, a named operator, and a value, applying the comparison through a server-owned operator map so no attacker text is ever interpreted.

## When It Is NOT This Issue

- **ast.literal_eval already in use:** a handler that reads only Python literals through literal_eval cannot execute calls and is not this sink.
- **Config-time eval of trusted files:** an interpreter that evaluates its own deployment config, never request data, is not request-reachable.
- **Sandbox is genuinely object-free:** an evaluator that receives only primitives and exposes no object with `__class__` leaves no introspection path, so a restricted-eval claim can hold.
- **NoSQL `$where` reflex:** a JavaScript expression running inside a Mongo query is query-layer injection with its own skill, not a server interpreter eval.
- **Reflected NameError without boolean tracking:** an error mentioning an undefined name proves parsing attempts, not that the response follows the expression truth value.
- **Self-only computed preview:** an expression affecting only the caller's throwaway view with no cross-user or process impact is not reportable here.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `code-injection-and-eval-dynamic-language-eval` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `code-injection-and-eval-dynamic-language-eval` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: code-injection-and-eval-dynamic-language-eval
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-94, CWE-95 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) - Web and Application (leaf)
- [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `code-injection-and-eval-dynamic-language-eval` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, CWE-95, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctftime (2), CYBER_CPT/xz_aliyun (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
