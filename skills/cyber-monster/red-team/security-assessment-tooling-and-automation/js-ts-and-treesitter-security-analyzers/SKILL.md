---
name: js-ts-and-treesitter-security-analyzers
description: "Develops multi-language and JavaScript/TypeScript static analyzers with `tree-sitter` S-expression queries and TypeScript Compiler/ESLint AST rules: finding dangerous DOM sinks, prototype merge sinks, missing Express/Next.js auth middleware, and SSRF fetch wrappers. Use when writing custom JS/TS or polyglot AST scanners."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["tree-sitter query", "eslint security rule", "typescript ast scanner", "s-expression ast"]
cwe: [CWE-79]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Js Ts and Treesitter Security Analyzers - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Structural analysis of JavaScript and TypeScript with tree-sitter: parse the file, run a query with captures for the node shapes you care about, and inspect captured nodes for context the grammar can prove — a call to `eval` whose argument is an identifier, a `dangerouslySetInnerHTML` prop, an assignment to `innerHTML`. Tree-sitter gives a real parse without a runtime, which is what makes the analysis usable in a pre-commit hook.

- **Queries are the rule language.** `query.captures` with named captures replaced ad-hoc node-type walks and is the stable API across grammar versions.
- **A capture is not a finding.** Captured nodes must be filtered by their parent, argument type, or binding, otherwise every occurrence of the identifier is reported.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the rule is about a call argument **THEN** capture the call and the argument, and require the argument node type to be non-literal before reporting.
2. **IF** the project already lints with ESLint **THEN** implement the rule as an ESLint rule with `RuleTester` so it runs in the existing pipeline instead of a separate script.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a grammar-pinned parser, and a query whose captures you can name on a positive and a negative sample — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** tree-sitter with the javascript/typescript grammar (`tree_sitter.Language`, `Query`, `query.captures`), ESLint 9 flat config with `RuleTester` for pipeline integration
- **Mandatory Self-Validation Command:** `python -c "import tree_sitter, tree_sitter_javascript; print(tree_sitter.__version__)"`

1. Confirm the target surface: pin the grammar and its version, because node type names differ between javascript and typescript grammars.
2. Choose the branch: tree-sitter query for cross-language scanning, ESLint rule when the project already runs ESLint and the rule needs scope analysis.
3. Define the differential: parse a positive sample and a negative sample, and require the capture set to differ exactly by the node under test.
4. Name the stop condition: a capture count per file plus a max file size, so a minified bundle cannot stall the hook.
5. Prove it: print the byte range and the source slice for every capture, so the finding points at a line a reviewer can open.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `tree_sitter.Language(lib_path, "javascript")` | Pins the grammar; a mismatched grammar yields node names that silently never match. |
| `Query(language, "(call_expression function: (identifier) @fn)")` | Declarative rule shape with named captures, portable across grammars. |
| `query.captures(root_node)` | Returns capture name, node pairs, which is the unit a rule filters and reports. |
| `ESLint RuleTester` | Fixture harness for the same rule inside the project's existing lint pipeline. |

## Worked Contrast

**Regex Search for a Dangerous Sink:**

```python
import re
src = open("app.js", encoding="utf-8").read()
if re.search(r"innerHTML\s*=", src):  # BUG: matches comments, strings and safe constant assignments
    print("XSS sink")
```

**Query Capture Filtered by Argument Shape:**

```python
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Query, QueryCursor

lang = Language(tsjs.language())
parser = Parser(lang)
query = Query(lang, """
(assignment_expression
  left: (member_expression property: (property_identifier) @prop)
  right: (_) @value)
""")
tree = parser.parse(open("app.js", "rb").read())
for _, caps in QueryCursor(query).matches(tree.root_node):
    for name, nodes in caps.items():
        if name == "prop" and nodes[0].text == b"innerHTML":
            val = caps["value"][0]
            if val.type not in ("string", "template_string"):
                print(val.start_point, val.text[:60])
```

**Why this matters:** A regex match on `innerHTML` fires for comments, documentation, and assignments of constant markup. Parsing and capturing the assignment's right-hand side lets the rule require a non-literal value, so the output is the set of assignments that can actually carry attacker-controlled data.

## When It Is NOT This Issue

- **Constant assignment.** `el.innerHTML = "<b>ok</b>"` is not a sink for untrusted data; require a non-literal right-hand side.
- **Framework auto-escaping.** A template engine that escapes by default changes the sink's semantics; confirm the sink is raw.
- **Grammar mismatch.** TypeScript syntax parsed with the JavaScript grammar produces error nodes and missed captures.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `tree_sitter.Language` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `js-ts-and-treesitter-security-analyzers` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: js-ts-and-treesitter-security-analyzers
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `tree_sitter.Language`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile js_ts_and_treesitter.py; python js_ts_and_treesitter.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `js-ts-and-treesitter-security-analyzers` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
