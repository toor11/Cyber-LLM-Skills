---
name: python-ast-and-libcst-security-linters
description: "Builds custom Python static security analyzers and codemods using stdlib `ast` and `libcst`: tracking dangerous call sites (`subprocess`, `pickle`, `yaml.load`, raw SQL f-strings), decorator-based authz checks on FastAPI/Flask/Django routes, and lossless secure autofixes. Use when writing bespoke Python security linters."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["python ast linter", "libcst codemod", "custom python sast", "ast nodevisitor security"]
cwe: [CWE-94]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Python AST and Libcst Security Linters - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Source-level analysis of Python with the standard `ast` module for read-only inspection, or `libcst` when the tool must also rewrite code while preserving formatting. Security rules use the AST to see resolved call shapes — a subscript into `os.environ`, a call to `eval` whose argument is a name rather than a literal, a `subprocess` call with `shell=True` — which text matching cannot distinguish.

- **Parse, do not grep.** `ast.parse` gives call arguments and keyword names, which is the difference between reporting `eval(user_input)` and reporting a comment that mentions eval.
- **CST for rewrites.** `libcst.CSTTransformer` preserves comments and formatting, so a fix commit reviews as a semantic change instead of a whole-file reformat.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the rule only reports **THEN** use `ast.NodeVisitor` and never touch the file.
2. **IF** the rule must apply a fix **THEN** use `libcst` and gate the rewrite behind an explicit flag so CI can run the check read-only.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a parseable source tree, a rule expressed as a node shape, and a positive and negative fixture — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11+ `ast` (`ast.parse`, `ast.NodeVisitor`, `ast.walk`) and `libcst` (`CSTTransformer`, `MetadataWrapper`) for rewrites
- **Mandatory Self-Validation Command:** `python -m compileall -q src && python -m ast fixtures/positive.py > /dev/null`

1. Confirm the target surface: pick the call or attribute the rule targets, and confirm its import path so a same-named local function is excluded.
2. Choose the branch: `ast` walk for detection, `libcst` transformer for autofix, or a hybrid where the detection runs on AST and the fix runs on CST.
3. Define the differential: run the rule over a positive and a negative fixture; the reported node count must differ by exactly the node under test.
4. Name the stop condition: a per-file node budget and a recursion guard, so deeply generated files do not blow the stack.
5. Prove it: report file, line, column, and the source segment via `ast.get_source_segment`, so the finding points at code a reviewer can open.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ast.parse(source, type_comments=True)` | Produces the tree every rule walks; `type_comments` keeps type comments available for annotation rules. |
| `ast.Call with func resolved through the import map` | Matching the resolved name rather than the bare identifier is what excludes shadowing. |
| `ast.get_source_segment` | Returns the exact source text for a node, which is the snippet a report should contain. |
| `libcst.CSTTransformer` | Rewrites while preserving formatting, so a fix diff contains only the change. |

## Worked Contrast

**Text Rule That Matches Shadowed Names:**

```python
import re
src = open("app.py", encoding="utf-8").read()
for i, line in enumerate(src.splitlines(), 1):
    if re.search(r"\beval\(", line):  # BUG: matches comments, strings and a local safe eval
        print(i, line)
```

**AST Rule That Resolves the Callable and Requires a Non-Literal Argument:**

```python
import ast

class Rule(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.hits = []

    def visit_Call(self, node: ast.Call) -> None:
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "eval" and node.args:
            arg = node.args[0]
            if not isinstance(arg, ast.Constant):
                self.hits.append((node.lineno, ast.get_source_segment(self.source, node)))
        self.generic_visit(node)

src = open("app.py", encoding="utf-8").read()
rule = Rule(src)
rule.visit(ast.parse(src))
print(rule.hits)
```

**Why this matters:** A regex on `eval(` fires for comments, docstrings, and a locally defined safe wrapper, so the report cannot be actioned. The AST rule sees the call node, checks that the callee is the bare builtin name, and requires a non-constant argument, which reduces the output to calls that can actually receive dynamic input.

## When It Is NOT This Issue

- **Shadowed builtin.** A module-level `def eval(...)` or a parameter named `eval` is not the builtin; require the resolved name.
- **Constant argument.** `eval("[1,2]")` on a literal is not the same risk class as `eval(request.data)`.
- **Rule fires in a vendored tree.** Third-party code under `vendor/` is not the project's to fix; exclude by path with a recorded policy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `ast.NodeVisitor` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `python-ast-and-libcst-security-linters` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: python-ast-and-libcst-security-linters
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `ast.NodeVisitor`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile python_ast_and_libcst.py; python python_ast_and_libcst.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `python-ast-and-libcst-security-linters` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
