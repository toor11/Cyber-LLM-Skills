---
name: code-injection-and-eval
description: Exploits dynamic code evaluation through eval, assert, preg_replace /e, create_function, script engines and expression evaluators. Use when input reaches a language-level evaluator rather than a shell or template.
family: web-and-application
tier: leaf
triggers: ["code injection", "eval injection", "dynamic evaluation", "assert injection", "expression injection"]
cwe: [CWE-94, CWE-95]
owasp: [A03:2021]
attack: [T1059]
capec: [CAPEC-242]
related: [code-injection-and-eval-expression-language, code-injection-and-eval-dynamic-language-eval, sql-injection, cross-site-scripting]
---

# Code Injection and Eval - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A request value crosses a trust boundary and is handed to a language-level evaluator that compiles and runs it as program source rather than reading it as data. The decision point is the evaluator call itself, eval, assert, create_function, preg_replace with the /e modifier, a JavaScript Function constructor, or a JVM ScriptEngine, not a template renderer and not a shell. Because the string becomes a syntax tree in the application runtime, the attacker gains whatever the host language exposes: arithmetic, property access, object construction, and ultimately process reach. Confirmation starts from an arithmetic or concatenation differential so a computed result or a compile error proves the string was parsed as code, before any execution primitive is ever exercised.

- **Precondition chain:** A request-controlled string reaches a language evaluator call, no closed allowlist pins that string to a fixed token set, the runtime actually compiles and executes the expression, and some observable (a computed value, a compile or type error, or a measurable delay) reflects that evaluation back.
- **Readable differential:** The same endpoint carrying an inert literal versus carrying a benign arithmetic or concatenation expression; a finding exists when the expression form returns the computed value or raises a language compile error, and the divergence disappears once the input is constrained to a closed grammar or token map.
- **Empirical grounding:** CWE-94 and CWE-95 (eval injection) define this class, and OWASP Top 10:2025 files it under A05:2025 Injection. No parent-class CVE is specific here, so the anchor stays at the CWE and OWASP category rather than a single advisory.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a Java expression evaluator such as SpEL, OGNL, or MVEL **THEN** switch to [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) (1 hop)
2. **IF** the sink is a scripting runtime eval or exec in PHP, Python, Ruby, or Node **THEN** switch to [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) (1 hop)
3. **IF** the value is rendered through a template engine rather than a raw evaluator **THEN** treat it as template directive execution and read [`ssti`](../ssti/SKILL.md)
4. **IF** the bytes are an object graph passed to a deserializer, not source text **THEN** model it as gadget-chain reconstruction and read [`insecure-deserialization`](../insecure-deserialization/SKILL.md)
5. **IF** the string is forwarded to a system shell rather than a language evaluator **THEN** reclassify as metacharacter neutralization and read [`os-command-injection`](../os-command-injection/SKILL.md)
6. **IF** the output is reflected into HTML and runs in the browser, not server-side **THEN** reclassify as client-side execution and read [`cross-site-scripting`](../cross-site-scripting/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no evaluator is reachable and the arithmetic differential stays flat **THEN** STOP and record a verified non-finding rather than escalating blind payloads

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Input is rendered by a server-side template engine | [`ssti`](../ssti/SKILL.md) | Invariant is template sandbox escape, not raw evaluator reachability |
| Bytes are an object graph fed to a deserializer | [`insecure-deserialization`](../insecure-deserialization/SKILL.md) | Invariant is gadget-chain trust during object reconstruction |
| String is handed to a system shell | [`os-command-injection`](../os-command-injection/SKILL.md) | Invariant is shell metacharacter neutralization in a different interpreter |
| Target matches `code-injection-and-eval-expression-language` | [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `code-injection-and-eval-dynamic-language-eval` | [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the evaluator call and classify the dialect.** Read the sink line, not the route handler, and record which primitive receives the value: eval, assert, create_function, preg_replace /e, a Function constructor, or a ScriptEngine. The dialect decides every later probe.
2. **Confirm the request value actually reaches that call.** Trace the parameter, header, cookie, or body field through any decode, trim, or type coercion to the evaluator argument, and note whether an allowlist or cast stands in the way.
3. **Pick the quietest oracle for this dialect.** A reflected computed value, a language compile or type error, or a bounded delay are three oracles with different noise; choose the arithmetic-result oracle first because it neither reads nor writes any record.
4. **Record a paired baseline.** Send an inert literal twice and capture body, status, and timing so natural variation forms a noise band before any expression is introduced.
5. **Apply the arithmetic or concatenation differential.** Replace the literal with a benign expression whose computed result is distinctive, and compare against the baseline; a matching computed value or a dialect-specific compile error selects the branch from evidence rather than guesswork.
6. **Stop condition.** Halt when the probe either (a) returns the computed value or a compile error that reverts once the input is pinned to a closed grammar, (b) produces no divergence across two baselines, or (c) would require a process-reach or file primitive to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is a single changed variable, an inert literal swapped for one benign expression, yielding a reproducible computed result or language compile error, plus the exact source line where the string reaches the evaluator. An HTTP 500 alone is not proof of eval reachability.
8. **Close with the structural fix and verify.** Remove the evaluator from the request path: parse to a closed grammar, map a caller token to a server-owned operation, or compute with a typed interpreter, then replay the arithmetic differential against the patched build to confirm the computed value no longer returns.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `eval(` or `assert(` receiving a request-derived string | Proves a raw language evaluator sink on PHP, Python, or Perl where the argument is compiled as source |
| `preg_replace` called with the `/e` modifier on user input | Proves the legacy PHP eval-on-replace path where the replacement is executed as code |
| `create_function` building a body from a request field | Proves a PHP closure factory that compiles attacker text into a callable on older runtimes |
| A JavaScript `Function(` constructor or `setTimeout` string argument | Proves a Node or browser evaluator that parses a string as a function body rather than data |
| A JVM `ScriptEngine.eval` call fed an HTTP parameter | Proves a Nashorn or GraalJS bridge where Java objects become reachable from the script |
| A benign arithmetic expression returning its computed result in the response | Proves the string was parsed as an expression on the server rather than echoed as a literal |
| A dialect-specific syntax error surfacing after an unbalanced token | Proves the evaluator compiled the input, identifying the language before any execution attempt |

## Worked Contrast

**Vulnerable pattern:**

```python
def render_metric(req):
    formula = req.params.get("formula", "0")
    # user text is compiled and executed as a Python expression
    return eval(formula)
```

**Hardened pattern:**

```python
import ast
import operator

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv}

def _calc(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
    raise ValueError("expression is outside the allowed arithmetic grammar")

def render_metric(req):
    tree = ast.parse(req.params.get("formula", "0"), mode="eval")
    return _calc(tree.body)
```

**Why this matters:** The vulnerable handler compiles arbitrary request text through eval, so any Python expression runs. The fix never calls eval: it parses to an AST and walks a closed arithmetic grammar, rejecting every node that is not a constant or an allowed binary operator, which removes the evaluator from the request path entirely.

## When It Is NOT This Issue

- **Arithmetic echoed by a calculator feature:** an endpoint that intentionally computes user arithmetic in a sandboxed numeric parser is behaving as designed; only reaching a language evaluator with host reach is the finding.
- **String match without reachability:** `eval(` present in a vendored library that the request never calls is dead code, not a confirmed sink.
- **HTTP 500 from a type error:** a generic exception page after malformed input proves input handling, not that the string was compiled and executed.
- **Closed token map already enforced:** a value looked up in a server-side dictionary and rejected when absent is safe even though it reaches the evaluator argument.
- **Template rendering mistaken for eval:** a `{{ }}` or `${ }` reflection is template evaluation with its own invariant and belongs to the SSTI or expression-language skills.
- **Caller-only numeric scope:** an expression that alters only the caller's own preview with no cross-tenant or process impact is not a reportable code-injection finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `code-injection-and-eval` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `code-injection-and-eval` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: code-injection-and-eval
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-94, CWE-95 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) - Web and Application (leaf)
- [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `code-injection-and-eval` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, CWE-95, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 49 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (28), hackerone_disclosed_reports (11), SecEval/owasp_wstg (2), SecEval/cs161_textbook (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
